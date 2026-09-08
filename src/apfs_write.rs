use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use crate::apfs_image::{
    APFS_VOL_ROLE_DATA, APFS_VOL_ROLE_PREBOOT, APFS_VOL_ROLE_RECOVERY, APFS_VOL_ROLE_SYSTEM,
    fletcher64_seal,
};
use crate::apfs_read::{DT_DIR, DT_REG, S_IFDIR, S_IFREG};
use crate::apfs_verify::{
    APFS_MAGIC, J_DIR_REC, J_FILE_EXTENT, J_INODE, NX_MAGIC, OBJ_PHYSICAL, OBJ_VIRTUAL,
    ROOT_DIR_INO_NUM, TYPE_BTREE, TYPE_FS, TYPE_NX_SUPERBLOCK,
};

const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const TYPE_SPACEMAN: u32 = 0x05;
const TYPE_SPACEMAN_CIB: u32 = 0x07;
const TYPE_SPACEMAN_FREE_QUEUE: u32 = 0x09;
const TYPE_OMAP: u32 = 0x0B;
const TYPE_CHECKPOINT_MAP: u32 = 0x0C;
const TYPE_NX_REAPER: u32 = 0x11;
const TYPE_BLOCKREFTREE: u32 = 0x0F;
const TYPE_SNAPMETATREE: u32 = 0x10;
const TYPE_FSTREE: u32 = 0x0E;
const TYPE_OMAP_SNAPSHOT: u32 = 0x13;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;

const CHECKPOINT_MAPPING_BYTES: usize = 40;
const CHUNK_INFO_BYTES: usize = 32;
const SPACEMAN_STRUCT_SIZE: u32 = 2520;

const APFS_BLOCK: u32 = 4096;
const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const ROOT_DIR_PARENT: u64 = 1;
const J_DSTREAM_ID: u64 = 6;
const J_SNAP_METADATA: u64 = 1;
const J_SNAP_NAME: u64 = 11;
const J_EXTENT: u64 = 2;
const J_OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;

const INODE_XFIELDS_OFFSET: usize = 0x5C;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const DSTREAM_BYTES: usize = 40;

const FIRST_FREE_INODE: u64 = 16;

const PRIV_DIR_INO_NUM: u64 = 3;

const IP_RING_BLOCKS: u64 = 16;
const IP_RING_LIVE: u64 = 1;

const CHECKPOINT_GEOMETRY_TABLE: &[(u64, u32, u32, u64)] = &[
    (64 * 1024 * 1024, 8, 160, 4),
    (128 * 1024 * 1024, 8, 304, 8),
    (512 * 1024 * 1024, 8, 388, 8),
    (1024 * 1024 * 1024, 16, 992, 8),
    (2560 * 1024 * 1024, 32, 2452, 8),
    (8192 * 1024 * 1024, 68, 6160, 8),
];

fn checkpoint_geometry(container_bytes: u64) -> Result<(u32, u32, u64), String> {
    CHECKPOINT_GEOMETRY_TABLE
        .iter()
        .filter(|(bytes, ..)| *bytes <= container_bytes)
        .max_by_key(|(bytes, ..)| *bytes)
        .map(|(_, desc_blocks, data_blocks, eph_min)| (*desc_blocks, *data_blocks, *eph_min))
        .ok_or_else(|| {
            format!(
                "container size {container_bytes} bytes is smaller than the smallest real APFS \
                 checkpoint-area geometry this writer has confirmed against fsck_apfs (64 MiB); \
                 refusing rather than inventing a checkpoint ring size"
            )
        })
}

// sfq_tree_node_limit: enforced by the live kernel driver on volume enumeration, by neither fsck_apfs nor apfs_verify.
const MAIN_FREE_QUEUE_NODE_LIMIT_TABLE: &[(u64, u16)] = &[
    (64 * 1024 * 1024, 4),
    (128 * 1024 * 1024, 8),
    (256 * 1024 * 1024, 15),
    (512 * 1024 * 1024, 29),
    (768 * 1024 * 1024, 44),
    (1024 * 1024 * 1024, 116),
    (1536 * 1024 * 1024, 174),
    (2048 * 1024 * 1024, 231),
    (2560 * 1024 * 1024, 289),
    (3072 * 1024 * 1024, 347),
    (4096 * 1024 * 1024, 512),
    (8192 * 1024 * 1024, 512),
];

fn main_free_queue_node_limit(container_bytes: u64) -> Result<u16, String> {
    MAIN_FREE_QUEUE_NODE_LIMIT_TABLE
        .iter()
        .filter(|(bytes, _)| *bytes <= container_bytes)
        .max_by_key(|(bytes, _)| *bytes)
        .map(|(_, limit)| *limit)
        .ok_or_else(|| {
            format!(
                "container size {container_bytes} bytes is smaller than the smallest real APFS \
                 main free-queue node limit this writer has confirmed against the live kernel \
                 APFS driver (64 MiB); refusing rather than inventing one"
            )
        })
}

fn put_u16(buf: &mut [u8], at: usize, v: u16) {
    buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn random16() -> Result<[u8; 16], String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|e| format!("reading random bytes: {e}"))?;
    Ok(bytes)
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

// apfs_volume_group_id/apfs_vol_uuid are straight hex over the bytes as stored, not a mixed-endian GUID encoding.
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

fn system_version_plist(os_name: &str) -> Result<Vec<u8>, String> {
    let mut dict = plist::Dictionary::new();
    dict.insert(
        "ProductName".to_string(),
        plist::Value::String(os_name.to_string()),
    );
    let mut bytes = Vec::new();
    plist::Value::Dictionary(dict)
        .to_writer_xml(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

struct Image {
    bytes: Vec<u8>,
    block_size: u32,
    block_count: u64,
    next: u64,
}

impl Image {
    fn new(block_size: u32, block_count: u64) -> Self {
        Self {
            bytes: vec![0u8; (block_count * u64::from(block_size)) as usize],
            block_size,
            block_count,
            next: 0,
        }
    }

    fn alloc(&mut self, blocks: u64) -> Result<u64, String> {
        let start = self.next;
        let end = start
            .checked_add(blocks)
            .ok_or("APFS container allocation overflowed")?;
        if end > self.block_count {
            return Err("APFS container is too small to hold its own structures".into());
        }
        self.next = end;
        Ok(start)
    }

    fn write_blocks(&mut self, paddr: u64, data: &[u8]) {
        let at = (paddr * u64::from(self.block_size)) as usize;
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }
}

// Both free lists stay at the empty-list sentinel {off: 0xFFFF, len: 0}, not 0.
fn write_free_space_fields(
    block: &mut [u8],
    key_base: usize,
    value_end: usize,
    key_bytes_used: usize,
    value_bytes_used: usize,
) {
    put_u16(block, 0x2C, key_bytes_used as u16); // btn_free_space.off
    let free_len = value_end - key_base - key_bytes_used - value_bytes_used;
    put_u16(block, 0x2E, free_len as u16); // btn_free_space.len
    put_u16(block, 0x30, 0xFFFF); // btn_key_free_list.off: empty, sentinel
    put_u16(block, 0x32, 0); // btn_key_free_list.len: nothing on it
    put_u16(block, 0x34, 0xFFFF); // btn_val_free_list.off: empty, sentinel
    put_u16(block, 0x36, 0); // btn_val_free_list.len: nothing on it
}

fn set_bt_flags(block: &mut [u8], block_size: u32, flags: u32) {
    let info = block_size as usize - BTREE_INFO_BYTES;
    put_u32(block, info, flags);
}

fn seal(oid: u64, xid: u64, o_type: u32, subtype: u32, mut block: Vec<u8>) -> Vec<u8> {
    put_u64(&mut block, 8, oid);
    put_u64(&mut block, 16, xid);
    put_u32(&mut block, 24, o_type);
    put_u32(&mut block, 28, subtype);
    fletcher64_seal(&mut block);
    block
}

fn build_leaf(block_size: u32, records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let bs = block_size as usize;
    let mut block = vec![0u8; bs];
    put_u16(&mut block, 0x20, BTNODE_ROOT | BTNODE_LEAF);
    put_u16(&mut block, 0x22, 0);
    put_u32(&mut block, 0x24, records.len() as u32);
    put_u16(&mut block, 0x28, 0);
    let toc_len = variable_toc_len(records.len()) as u16;
    put_u16(&mut block, 0x2A, toc_len);
    let toc = BTNODE_TOC_BASE;
    let key_base = toc + toc_len as usize;
    let value_end = bs - BTREE_INFO_BYTES;
    let mut key_cursor = 0usize;
    let mut value_cursor = 0usize;
    for (index, (key, value)) in records.iter().enumerate() {
        let at = toc + index * 8;
        put_u16(&mut block, at, key_cursor as u16);
        put_u16(&mut block, at + 2, key.len() as u16);
        let value_offset = value_cursor + value.len();
        put_u16(&mut block, at + 4, value_offset as u16);
        put_u16(&mut block, at + 6, value.len() as u16);
        let key_at = key_base + key_cursor;
        let value_at = value_end
            .checked_sub(value_offset)
            .filter(|at| *at >= key_base)
            .ok_or("b-tree leaf overflowed its node")?;
        if key_at + key.len() > value_at {
            return Err("b-tree leaf overflowed its node".into());
        }
        block[key_at..key_at + key.len()].copy_from_slice(key);
        block[value_at..value_at + value.len()].copy_from_slice(value);
        key_cursor += key.len();
        value_cursor = value_offset;
    }
    write_free_space_fields(&mut block, key_base, value_end, key_cursor, value_cursor);
    let info = bs - BTREE_INFO_BYTES;
    put_u32(&mut block, info, 0); // bt_flags
    put_u32(&mut block, info + 4, block_size); // bt_node_size
    put_u32(&mut block, info + 8, 0); // bt_key_size (variable)
    put_u32(&mut block, info + 12, 0); // bt_val_size (variable)
    let longest_key = records.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    let longest_val = records.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
    put_u32(&mut block, info + 16, longest_key as u32);
    put_u32(&mut block, info + 20, longest_val as u32);
    put_u64(&mut block, info + 24, records.len() as u64); // bt_key_count
    put_u64(&mut block, info + 32, 1); // bt_node_count
    Ok(block)
}

const OMAP_KEY_BYTES: usize = 16;
const OMAP_VALUE_BYTES: usize = 16;
const FIXED_TOC_ENTRY_BYTES: usize = 4;

fn build_omap_leaf(block_size: u32, records: &[(Vec<u8>, Vec<u8>)]) -> Result<Vec<u8>, String> {
    build_fixed_kv_leaf(
        block_size,
        OMAP_KEY_BYTES,
        OMAP_VALUE_BYTES,
        0x12, // bt_flags: BTREE_PHYSICAL | BTREE_SEQUENTIAL_INSERT
        records,
    )
}

const OMAP_SNAPSHOT_KEY_BYTES: usize = 8;
const OMAP_SNAPSHOT_VALUE_BYTES: usize = 16;

fn build_omap_snapshot_leaf(block_size: u32, xid: u64) -> Result<Vec<u8>, String> {
    let key = xid.to_le_bytes().to_vec();
    let value = vec![0u8; OMAP_SNAPSHOT_VALUE_BYTES];
    build_fixed_kv_leaf(
        block_size,
        OMAP_SNAPSHOT_KEY_BYTES,
        OMAP_SNAPSHOT_VALUE_BYTES,
        0x12, // bt_flags: BTREE_PHYSICAL | BTREE_SEQUENTIAL_INSERT
        &[(key, value)],
    )
}

fn build_fixed_kv_leaf(
    block_size: u32,
    key_size: usize,
    val_size: usize,
    bt_flags: u32,
    records: &[(Vec<u8>, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    let bs = block_size as usize;
    let mut block = vec![0u8; bs];
    put_u16(
        &mut block,
        0x20,
        BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE,
    );
    put_u16(&mut block, 0x22, 0);
    put_u32(&mut block, 0x24, records.len() as u32);
    put_u16(&mut block, 0x28, 0);
    let toc = BTNODE_TOC_BASE;
    let capacity = (bs - toc) / (FIXED_TOC_ENTRY_BYTES + key_size + val_size);
    let toc_len = capacity * FIXED_TOC_ENTRY_BYTES;
    put_u16(&mut block, 0x2A, toc_len as u16);
    let key_base = toc + toc_len;
    let value_end = bs - BTREE_INFO_BYTES;
    if records.len() > capacity {
        return Err("fixed key/value leaf overflowed its node".into());
    }
    for (index, (key, value)) in records.iter().enumerate() {
        if key.len() != key_size || value.len() != val_size {
            return Err("record is not this tree's fixed key/value size".into());
        }
        let at = toc + index * FIXED_TOC_ENTRY_BYTES;
        let key_offset = index * key_size;
        let value_offset = (index + 1) * val_size;
        put_u16(&mut block, at, key_offset as u16);
        put_u16(&mut block, at + 2, value_offset as u16);
        let key_at = key_base + key_offset;
        let value_at = value_end - value_offset;
        if key_at + key_size > value_at {
            return Err("fixed key/value leaf overflowed its node".into());
        }
        block[key_at..key_at + key_size].copy_from_slice(key);
        block[value_at..value_at + val_size].copy_from_slice(value);
    }
    write_free_space_fields(
        &mut block,
        key_base,
        value_end,
        records.len() * key_size,
        records.len() * val_size,
    );
    let info = bs - BTREE_INFO_BYTES;
    put_u32(&mut block, info, bt_flags);
    put_u32(&mut block, info + 4, block_size); // bt_node_size
    put_u32(&mut block, info + 8, key_size as u32); // bt_key_size
    put_u32(&mut block, info + 12, val_size as u32); // bt_val_size
    let (longest_key, longest_val) = if records.is_empty() {
        (0, 0)
    } else {
        (key_size as u32, val_size as u32)
    };
    put_u32(&mut block, info + 16, longest_key);
    put_u32(&mut block, info + 20, longest_val);
    put_u64(&mut block, info + 24, records.len() as u64); // bt_key_count
    put_u64(&mut block, info + 32, 1); // bt_node_count
    Ok(block)
}

fn build_omap_phys(
    block_size: u32,
    tree_paddr: u64,
    om_flags: u32,
    snapshot_tree_paddr: u64,
    snap_count: u32,
    most_recent_snap_xid: u64,
) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_u32(&mut block, 0x20, om_flags);
    put_u32(&mut block, 0x24, snap_count); // om_snap_count
    put_u32(&mut block, 0x28, OBJ_PHYSICAL | TYPE_BTREE); // om_tree_type
    put_u32(&mut block, 0x2C, OBJ_PHYSICAL | TYPE_BTREE); // om_snapshot_tree_type
    put_u64(&mut block, 0x30, tree_paddr); // om_tree_oid
    put_u64(&mut block, 0x38, snapshot_tree_paddr); // om_snapshot_tree_oid
    put_u64(&mut block, 0x40, most_recent_snap_xid); // om_most_recent_snap
    block
}

fn omap_kv(oid: u64, xid: u64, paddr: u64, block_size: u32) -> (Vec<u8>, Vec<u8>) {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&oid.to_le_bytes());
    key.extend_from_slice(&xid.to_le_bytes());
    let mut value = vec![0u8; 16];
    put_u32(&mut value, 4, block_size);
    put_u64(&mut value, 8, paddr);
    (key, value)
}

pub(crate) fn inode_key(oid: u64) -> Vec<u8> {
    ((J_INODE << 60) | oid).to_le_bytes().to_vec()
}

const INODE_INTERNAL_FLAGS: u64 = 0x8000;

pub(crate) fn dir_inode_val(parent: u64, oid: u64, nchildren: u32) -> Vec<u8> {
    let mut value = vec![0u8; INODE_XFIELDS_OFFSET];
    put_u64(&mut value, 0x00, parent);
    put_u64(&mut value, 0x08, oid); // private_id
    put_u64(&mut value, 0x30, INODE_INTERNAL_FLAGS);
    put_u32(&mut value, 0x38, nchildren);
    put_u16(&mut value, 0x50, S_IFDIR | 0o755);
    value
}

pub(crate) fn file_inode_val(parent: u64, oid: u64, size: u64, alloced: u64) -> Vec<u8> {
    let mut value = vec![0u8; INODE_XFIELDS_OFFSET];
    put_u64(&mut value, 0x00, parent);
    put_u64(&mut value, 0x08, oid); // private_id
    put_u64(&mut value, 0x30, INODE_INTERNAL_FLAGS);
    put_u32(&mut value, 0x38, 1); // nlink
    put_u16(&mut value, 0x50, S_IFREG | 0o644);
    let mut dstream = vec![0u8; DSTREAM_BYTES];
    put_u64(&mut dstream, 0x00, size);
    put_u64(&mut dstream, 0x08, alloced);
    put_u64(&mut dstream, 0x18, size); // total_bytes_written
    value.extend_from_slice(&1u16.to_le_bytes()); // xf_num_exts
    value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes()); // xf_used_data
    value.push(INO_EXT_TYPE_DSTREAM);
    value.push(0);
    value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes());
    value.extend_from_slice(&dstream);
    value
}

pub(crate) fn drec_key(parent: u64, name: &str) -> Result<Vec<u8>, String> {
    let hash = name_hash(name)?;
    let mut key = ((J_DIR_REC << 60) | parent).to_le_bytes().to_vec();
    let name_len = (name.len() + 1) as u32;
    let packed = (hash << 10) | name_len;
    key.extend_from_slice(&packed.to_le_bytes());
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    Ok(key)
}

pub(crate) fn drec_val(target: u64, dt: u16) -> Vec<u8> {
    let mut value = vec![0u8; 0x12];
    put_u64(&mut value, 0, target);
    put_u16(&mut value, 0x10, dt);
    value
}

pub(crate) fn dstream_id_key(oid: u64) -> Vec<u8> {
    ((J_DSTREAM_ID << 60) | oid).to_le_bytes().to_vec()
}

pub(crate) fn dstream_id_val(refcnt: u32) -> Vec<u8> {
    refcnt.to_le_bytes().to_vec()
}

pub(crate) fn extent_key(oid: u64) -> Vec<u8> {
    let mut key = ((J_FILE_EXTENT << 60) | oid).to_le_bytes().to_vec();
    key.extend_from_slice(&0u64.to_le_bytes());
    key
}

pub(crate) fn extent_val(len: u64, phys: u64) -> Vec<u8> {
    let mut value = vec![0u8; 24];
    put_u64(&mut value, 0, len);
    put_u64(&mut value, 8, phys);
    put_u64(&mut value, 16, 0);
    value
}

fn snap_metadata_key(xid: u64) -> Vec<u8> {
    ((J_SNAP_METADATA << 60) | xid).to_le_bytes().to_vec()
}

fn snap_metadata_val(
    extentref_tree_oid: u64,
    sblock_oid: u64,
    create_time: u64,
    change_time: u64,
    name: &str,
) -> Vec<u8> {
    let mut value = vec![0u8; 0x32];
    put_u64(&mut value, 0x00, extentref_tree_oid);
    put_u64(&mut value, 0x08, sblock_oid);
    put_u64(&mut value, 0x10, create_time);
    put_u64(&mut value, 0x18, change_time);
    put_u64(&mut value, 0x20, PRIV_DIR_INO_NUM);
    put_u32(&mut value, 0x28, OBJ_PHYSICAL | TYPE_BTREE); // extentref_tree_type
    put_u32(&mut value, 0x2C, 0); // flags
    let name_len = (name.len() + 1) as u16;
    put_u16(&mut value, 0x30, name_len);
    value.extend_from_slice(name.as_bytes());
    value.push(0);
    value
}

fn snap_name_key(name: &str) -> Vec<u8> {
    let mut key = ((J_SNAP_NAME << 60) | J_OBJ_ID_MASK).to_le_bytes().to_vec();
    let name_len = (name.len() + 1) as u16;
    key.extend_from_slice(&name_len.to_le_bytes());
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    key
}

fn snap_name_val(xid: u64) -> Vec<u8> {
    xid.to_le_bytes().to_vec()
}

fn now_apfs_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0)
}

fn phys_ext_key(phys_start: u64) -> Vec<u8> {
    ((J_EXTENT << 60) | phys_start).to_le_bytes().to_vec()
}

fn phys_ext_val(len_blocks: u64, owning_obj_id: u64, refcnt: i32) -> Vec<u8> {
    let mut value = vec![0u8; 20];
    let len_and_kind = len_blocks | (1u64 << 60); // kind 1: APFS_KIND_NEW
    put_u64(&mut value, 0, len_and_kind);
    put_u64(&mut value, 8, owning_obj_id);
    value[16..20].copy_from_slice(&refcnt.to_le_bytes());
    value
}

pub(crate) fn record_sort_key(key: &[u8]) -> (u64, u64, Vec<u8>) {
    let header = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let obj_id = header & J_OBJ_ID_MASK;
    let kind = header >> 60;
    let tail = if kind == J_DIR_REC && key.len() >= 12 {
        let prefix = u32::from_le_bytes(key[8..12].try_into().unwrap());
        let mut tail = prefix.to_be_bytes().to_vec();
        tail.extend_from_slice(&key[12..]);
        tail
    } else if kind == J_SNAP_NAME && key.len() >= 10 {
        key[10..].to_vec()
    } else {
        key[8..].to_vec()
    };
    (obj_id, kind, tail)
}

#[derive(Clone, Copy)]
pub(crate) struct TreeLayout {
    pub(crate) fixed: Option<(usize, usize)>,
    pub(crate) flags: u32,
    pub(crate) subtype: u32,
}

// fsck_apfs rejects a tight TOC on fixed-KV nodes (`invalid btn_table_space`).
fn fixed_toc_len(block_size: usize, key_size: usize, val_size: usize) -> usize {
    let capacity = (block_size - BTNODE_TOC_BASE) / (FIXED_TOC_ENTRY_BYTES + key_size + val_size);
    capacity * FIXED_TOC_ENTRY_BYTES
}

// fsck_apfs rejects btn_table_space.len == 0 on variable-KV nodes (empty extentref trees).
const MIN_VARIABLE_TOC_SLOTS: usize = 8;

fn variable_toc_len(nkeys: usize) -> usize {
    nkeys.max(MIN_VARIABLE_TOC_SLOTS) * 8
}

fn node_bytes(
    records: &[(Vec<u8>, Vec<u8>)],
    layout: TreeLayout,
    root: bool,
    level: u16,
    block_size: usize,
) -> usize {
    let toc = if let Some((ks, vs)) = layout.fixed {
        let vs = if level == 0 { vs } else { 8 };
        fixed_toc_len(block_size, ks, vs)
    } else {
        variable_toc_len(records.len())
    };
    BTNODE_TOC_BASE
        + toc
        + records
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
        + if root { BTREE_INFO_BYTES } else { 0 }
}

fn encode_tree_node(
    block_size: u32,
    records: &[(Vec<u8>, Vec<u8>)],
    layout: TreeLayout,
    level: u16,
    root: bool,
    totals: (u64, u64, usize, usize),
) -> Result<Vec<u8>, String> {
    let bs = block_size as usize;
    if node_bytes(records, layout, root, level, bs) > bs {
        return Err("b-tree records exceed node capacity".into());
    }
    let mut block = vec![0; bs];
    let flags = if root { BTNODE_ROOT } else { 0 }
        | if level == 0 { BTNODE_LEAF } else { 0 }
        | if layout.fixed.is_some() {
            BTNODE_FIXED_KV_SIZE
        } else {
            0
        };
    put_u16(&mut block, 0x20, flags);
    put_u16(&mut block, 0x22, level);
    put_u32(&mut block, 0x24, records.len() as u32);
    let stride = if layout.fixed.is_some() { 4 } else { 8 };
    let toc_len = if let Some((ks, vs)) = layout.fixed {
        let vs = if level == 0 { vs } else { 8 };
        fixed_toc_len(bs, ks, vs)
    } else {
        variable_toc_len(records.len())
    };
    put_u16(&mut block, 0x2A, toc_len as u16);
    let key_base = BTNODE_TOC_BASE + toc_len;
    let value_end = bs - if root { BTREE_INFO_BYTES } else { 0 };
    let (mut key_used, mut value_used) = (0, 0);
    for (i, (key, value)) in records.iter().enumerate() {
        if let Some((ks, vs)) = layout.fixed
            && (key.len() != ks || value.len() != if level == 0 { vs } else { 8 })
        {
            return Err("invalid fixed-size b-tree record".into());
        }
        let at = BTNODE_TOC_BASE + i * stride;
        value_used += value.len();
        put_u16(&mut block, at, key_used as u16);
        if layout.fixed.is_some() {
            put_u16(&mut block, at + 2, value_used as u16);
        } else {
            put_u16(&mut block, at + 2, key.len() as u16);
            put_u16(&mut block, at + 4, value_used as u16);
            put_u16(&mut block, at + 6, value.len() as u16);
        }
        block[key_base + key_used..key_base + key_used + key.len()].copy_from_slice(key);
        block[value_end - value_used..value_end - value_used + value.len()].copy_from_slice(value);
        key_used += key.len();
    }
    write_free_space_fields(&mut block, key_base, value_end, key_used, value_used);
    if root {
        let info = bs - BTREE_INFO_BYTES;
        put_u32(&mut block, info, layout.flags);
        put_u32(&mut block, info + 4, block_size);
        let (ks, vs) = layout.fixed.unwrap_or((0, 0));
        put_u32(&mut block, info + 8, ks as u32);
        put_u32(&mut block, info + 12, vs as u32);
        put_u32(&mut block, info + 16, totals.2 as u32);
        put_u32(&mut block, info + 20, totals.3 as u32);
        put_u64(&mut block, info + 24, totals.0);
        put_u64(&mut block, info + 32, totals.1);
    }
    Ok(block)
}

pub(crate) trait TreeStore {
    fn block_size(&self) -> u32;
    fn alloc(&mut self, blocks: u64) -> Result<u64, String>;
    fn write_blocks(&mut self, paddr: u64, data: &[u8]) -> Result<(), String>;
}

impl TreeStore for Image {
    fn block_size(&self) -> u32 {
        self.block_size
    }
    fn alloc(&mut self, blocks: u64) -> Result<u64, String> {
        Image::alloc(self, blocks)
    }
    fn write_blocks(&mut self, paddr: u64, data: &[u8]) -> Result<(), String> {
        Image::write_blocks(self, paddr, data);
        Ok(())
    }
}

pub(crate) fn write_tree(
    image: &mut impl TreeStore,
    records: Vec<(Vec<u8>, Vec<u8>)>,
    layout: TreeLayout,
    xid: u64,
    virtual_root: Option<u64>,
    next_oid: &mut u64,
) -> Result<(u64, Vec<(u64, u64)>), String> {
    let root_paddr = image.alloc(1)?;
    let root_oid = virtual_root.unwrap_or(root_paddr);
    let storage = if virtual_root.is_some() {
        OBJ_VIRTUAL
    } else {
        OBJ_PHYSICAL
    };
    let mut mappings = vec![(root_oid, root_paddr)];
    let mut totals = (
        records.len() as u64,
        1,
        records.iter().map(|(k, _)| k.len()).max().unwrap_or(0),
        records.iter().map(|(_, v)| v.len()).max().unwrap_or(0),
    );
    let mut level = 0u16;
    let mut current = records;
    while node_bytes(&current, layout, true, level, image.block_size() as usize)
        > image.block_size() as usize
    {
        let mut parents = Vec::new();
        let mut start = 0;
        while start < current.len() {
            let mut end = start;
            while end < current.len()
                && node_bytes(
                    &current[start..=end],
                    layout,
                    false,
                    level,
                    image.block_size() as usize,
                ) <= image.block_size() as usize
            {
                end += 1;
            }
            if end == start {
                return Err("single b-tree record exceeds node capacity".into());
            }
            let paddr = image.alloc(1)?;
            let oid = if virtual_root.is_some() {
                let oid = *next_oid;
                *next_oid = next_oid.checked_add(1).ok_or("b-tree object ID overflow")?;
                oid
            } else {
                paddr
            };
            let bytes = encode_tree_node(
                image.block_size(),
                &current[start..end],
                layout,
                level,
                false,
                totals,
            )?;
            image.write_blocks(
                paddr,
                &seal(
                    oid,
                    xid,
                    storage | crate::apfs_verify::TYPE_BTREE_NODE,
                    layout.subtype,
                    bytes,
                ),
            )?;
            mappings.push((oid, paddr));
            totals.1 += 1;
            parents.push((current[start].0.clone(), oid.to_le_bytes().to_vec()));
            start = end;
        }
        if parents.len() >= current.len() && level != 0 {
            return Err("b-tree separator keys exceed branching capacity".into());
        }
        current = parents;
        level = level.checked_add(1).ok_or("b-tree depth overflow")?;
    }
    let bytes = encode_tree_node(image.block_size(), &current, layout, level, true, totals)?;
    image.write_blocks(
        root_paddr,
        &seal(root_oid, xid, storage | TYPE_BTREE, layout.subtype, bytes),
    )?;
    Ok((root_paddr, mappings))
}

struct FsBuilder<'a> {
    image: &'a mut Image,
    records: Vec<(Vec<u8>, Vec<u8>)>,
    dirs: HashMap<Vec<String>, u64>,
    nchildren: HashMap<u64, u32>,
    next_oid: u64,
    inode_record_index: HashMap<u64, usize>,
    file_extents: Vec<(u64, u64, u64)>,
}

impl<'a> FsBuilder<'a> {
    fn new(image: &'a mut Image, first_oid: u64) -> Result<Self, String> {
        let mut builder = Self {
            image,
            records: Vec::new(),
            dirs: HashMap::new(),
            nchildren: HashMap::new(),
            next_oid: first_oid.max(FIRST_FREE_INODE),
            inode_record_index: HashMap::new(),
            file_extents: Vec::new(),
        };
        builder.dirs.insert(Vec::new(), ROOT_DIR_INO_NUM);
        builder.nchildren.insert(ROOT_DIR_INO_NUM, 0);
        builder.records.push((
            drec_key(ROOT_DIR_PARENT, "root")?,
            drec_val(ROOT_DIR_INO_NUM, DT_DIR),
        ));
        let index = builder.records.len();
        builder.records.push((
            inode_key(ROOT_DIR_INO_NUM),
            dir_inode_val(ROOT_DIR_PARENT, ROOT_DIR_INO_NUM, 0),
        ));
        builder.inode_record_index.insert(ROOT_DIR_INO_NUM, index);
        Ok(builder)
    }

    fn ensure_dir(&mut self, path: &[&str]) -> Result<u64, String> {
        let key: Vec<String> = path.iter().map(|s| s.to_ascii_lowercase()).collect();
        if let Some(oid) = self.dirs.get(&key).copied() {
            return Ok(oid);
        }
        let name = path[path.len() - 1];
        let parent_oid = self.ensure_dir(&path[..path.len() - 1])?;
        let oid = self.next_oid;
        self.next_oid += 1;
        self.records
            .push((drec_key(parent_oid, name)?, drec_val(oid, DT_DIR)));
        *self.nchildren.entry(parent_oid).or_insert(0) += 1;
        let index = self.records.len();
        self.records
            .push((inode_key(oid), dir_inode_val(parent_oid, oid, 0)));
        self.inode_record_index.insert(oid, index);
        self.nchildren.insert(oid, 0);
        self.dirs.insert(key, oid);
        Ok(oid)
    }

    fn add_file(&mut self, dir_path: &[&str], name: &str, data: &[u8]) -> Result<(), String> {
        let parent_oid = self.ensure_dir(dir_path)?;
        let oid = self.next_oid;
        self.next_oid += 1;
        let block_size = u64::from(self.image.block_size);
        let need_blocks = (data.len() as u64).div_ceil(block_size).max(1);
        let paddr = self.image.alloc(need_blocks)?;
        let alloced = need_blocks * block_size;
        let mut buffer = vec![0u8; alloced as usize];
        buffer[..data.len()].copy_from_slice(data);
        self.image.write_blocks(paddr, &buffer);
        self.file_extents.push((paddr, need_blocks, oid));

        self.records
            .push((drec_key(parent_oid, name)?, drec_val(oid, DT_REG)));
        *self.nchildren.entry(parent_oid).or_insert(0) += 1;
        self.records.push((
            inode_key(oid),
            file_inode_val(parent_oid, oid, data.len() as u64, alloced),
        ));
        self.records
            .push((extent_key(oid), extent_val(alloced, paddr)));
        self.records.push((dstream_id_key(oid), dstream_id_val(1)));
        Ok(())
    }

    fn file_extents(&self) -> Vec<(u64, u64, u64)> {
        self.file_extents.clone()
    }

    fn finish(
        mut self,
        virtual_oid: u64,
        xid: u64,
        next_oid: &mut u64,
    ) -> Result<(Vec<(u64, u64)>, u64), String> {
        for (oid, count) in &self.nchildren {
            let index = self.inode_record_index[oid];
            put_u32(&mut self.records[index].1, 0x38, *count);
        }
        self.records.sort_by_key(|(key, _)| record_sort_key(key));
        *next_oid = (*next_oid).max(self.next_oid);
        let (_, mappings) = write_tree(
            self.image,
            self.records,
            TreeLayout {
                fixed: None,
                flags: 0x42,
                subtype: TYPE_FSTREE,
            },
            xid,
            Some(virtual_oid),
            next_oid,
        )?;
        Ok((mappings, *next_oid))
    }
}

#[allow(clippy::too_many_arguments)]
fn build_apsb(
    block_size: u32,
    fs_index: u32,
    name: &str,
    role: u16,
    vol_uuid: [u8; 16],
    group_id: [u8; 16],
    omap_paddr: u64,
    fs_tree_oid: u64,
    extentref_paddr: u64,
    snapmeta_paddr: u64,
    next_obj_id: u64,
    num_snapshots: u64,
) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_u32(&mut block, 0x20, APFS_MAGIC);
    put_u32(&mut block, 0x24, fs_index);
    put_u64(&mut block, 0x28, 0x2);
    put_u64(&mut block, 0x30, 0); // read-only compatible features
    put_u64(&mut block, 0x38, APFS_INCOMPAT_CASE_INSENSITIVE);
    put_u64(&mut block, 0x48, 0); // reserve_block_count
    put_u64(&mut block, 0x50, 0); // quota_block_count
    put_u64(&mut block, 0x58, 0); // apfs_fs_alloc_count
    put_u32(&mut block, 0x74, OBJ_VIRTUAL | TYPE_BTREE);
    put_u32(&mut block, 0x78, OBJ_PHYSICAL | TYPE_BTREE);
    put_u32(&mut block, 0x7C, OBJ_PHYSICAL | TYPE_BTREE);
    put_u64(&mut block, 0x80, omap_paddr);
    put_u64(&mut block, 0x88, fs_tree_oid);
    put_u64(&mut block, 0x90, extentref_paddr);
    put_u64(&mut block, 0x98, snapmeta_paddr);
    put_u64(&mut block, 0xA0, 0); // apfs_revert_to_xid: no pending revert
    put_u64(&mut block, 0xA8, 0); // apfs_revert_to_sblock_oid (guess, unused)
    put_u64(&mut block, 0xB0, next_obj_id);
    put_u64(&mut block, 0xD8, num_snapshots); // apfs_num_snapshots
    block[0xF0..0x100].copy_from_slice(&vol_uuid);
    put_u64(&mut block, 0x108, APFS_FS_UNENCRYPTED);
    let name_bytes = name.as_bytes();
    block[0x2C0..0x2C0 + name_bytes.len()].copy_from_slice(name_bytes);
    put_u32(&mut block, 0x3C0, 3);
    put_u16(&mut block, 0x3C4, role);
    put_u64(&mut block, 0x3C8, 0); // root_to_xid
    block[0x3F0..0x400].copy_from_slice(&group_id);
    put_u64(&mut block, 0x400, 0); // integrity_meta_oid: unsealed
    put_u64(&mut block, 0x408, 0); // fext_tree_oid: extents live in the catalog
    put_u32(&mut block, 0x410, 0); // fext_tree_type
    block
}

#[allow(clippy::too_many_arguments)]
fn build_volume(
    image: &mut Image,
    next_oid: &mut u64,
    fs_index: u32,
    name: &str,
    role: u16,
    group_id: [u8; 16],
    xid: u64,
    snapshot_name: Option<&str>,
    populate: impl FnOnce(&mut FsBuilder) -> Result<(), String>,
) -> Result<(u64, u64), String> {
    let fs_tree_oid = {
        let oid = *next_oid;
        *next_oid += 1;
        oid
    };
    let apsb_oid = {
        let oid = *next_oid;
        *next_oid += 1;
        oid
    };

    let mut builder = FsBuilder::new(image, *next_oid)?;
    populate(&mut builder)?;
    let file_extents = builder.file_extents();
    let (mut fs_mappings, next_inode) = builder.finish(fs_tree_oid, xid, next_oid)?;
    fs_mappings.sort_by_key(|(oid, _)| *oid);
    let entries = fs_mappings
        .iter()
        .map(|(oid, paddr)| omap_kv(*oid, xid, *paddr, image.block_size))
        .collect();
    let (vol_omap_tree_paddr, _) = write_tree(
        image,
        entries,
        TreeLayout {
            fixed: Some((OMAP_KEY_BYTES, OMAP_VALUE_BYTES)),
            flags: 0x12,
            subtype: TYPE_OMAP,
        },
        xid,
        None,
        next_oid,
    )?;

    let omap_snapshot_tree_paddr = if snapshot_name.is_some() {
        let paddr = image.alloc(1)?;
        let leaf = build_omap_snapshot_leaf(image.block_size, xid)?;
        let sealed = seal(
            paddr,
            xid,
            OBJ_PHYSICAL | TYPE_BTREE,
            TYPE_OMAP_SNAPSHOT,
            leaf,
        );
        image.write_blocks(paddr, &sealed);
        paddr
    } else {
        0
    };
    let (om_snap_count, om_most_recent_snap) = if snapshot_name.is_some() {
        (1, xid)
    } else {
        (0, 0)
    };
    let vol_omap_paddr = image.alloc(1)?;
    let omap_block = build_omap_phys(
        image.block_size,
        vol_omap_tree_paddr,
        0,
        omap_snapshot_tree_paddr,
        om_snap_count,
        om_most_recent_snap,
    );
    let sealed_omap = seal(vol_omap_paddr, xid, OBJ_PHYSICAL | TYPE_OMAP, 0, omap_block);
    image.write_blocks(vol_omap_paddr, &sealed_omap);

    let mut extentref_records: Vec<(Vec<u8>, Vec<u8>)> = file_extents
        .iter()
        .map(|(paddr, blocks, owning_oid)| {
            (phys_ext_key(*paddr), phys_ext_val(*blocks, *owning_oid, 1))
        })
        .collect();
    extentref_records.sort_by_key(|(key, _)| record_sort_key(key));

    let layout = TreeLayout {
        fixed: None,
        flags: 0x52,
        subtype: TYPE_BLOCKREFTREE,
    };
    let (extentref_paddr, _) = write_tree(
        image,
        extentref_records.clone(),
        layout,
        xid,
        None,
        next_oid,
    )?;
    let snapshot_extentref_paddr = if snapshot_name.is_some() {
        write_tree(image, extentref_records, layout, xid, None, next_oid)?.0
    } else {
        0
    };

    let frozen_apsb_paddr = if snapshot_name.is_some() {
        image.alloc(1)?
    } else {
        0
    };

    let snapmeta_paddr = image.alloc(1)?;
    let mut snapmeta_records = if let Some(snapshot_name) = snapshot_name {
        let now = now_apfs_nanos();
        vec![
            (
                snap_metadata_key(xid),
                snap_metadata_val(
                    snapshot_extentref_paddr,
                    frozen_apsb_paddr,
                    now,
                    now,
                    snapshot_name,
                ),
            ),
            (snap_name_key(snapshot_name), snap_name_val(xid)),
        ]
    } else {
        Vec::new()
    };
    snapmeta_records.sort_by_key(|(key, _)| record_sort_key(key));
    let mut snapmeta = build_leaf(image.block_size, &snapmeta_records)?;
    set_bt_flags(&mut snapmeta, image.block_size, 0x52);
    let sealed_snapmeta = seal(
        snapmeta_paddr,
        xid,
        OBJ_PHYSICAL | TYPE_BTREE,
        TYPE_SNAPMETATREE,
        snapmeta,
    );
    image.write_blocks(snapmeta_paddr, &sealed_snapmeta);

    let vol_uuid = random16()?;
    let num_snapshots = u64::from(snapshot_name.is_some());
    let apsb = build_apsb(
        image.block_size,
        fs_index,
        name,
        role,
        vol_uuid,
        group_id,
        vol_omap_paddr,
        fs_tree_oid,
        extentref_paddr,
        snapmeta_paddr,
        next_inode,
        num_snapshots,
    );
    let apsb_paddr = image.alloc(1)?;
    let sealed_apsb = seal(apsb_oid, xid, OBJ_VIRTUAL | TYPE_FS, 0, apsb.clone());
    image.write_blocks(apsb_paddr, &sealed_apsb);

    if snapshot_name.is_some() {
        let sealed_frozen_apsb = seal(frozen_apsb_paddr, xid, OBJ_PHYSICAL | TYPE_FS, 0, apsb);
        image.write_blocks(frozen_apsb_paddr, &sealed_frozen_apsb);
    }

    Ok((apsb_oid, apsb_paddr))
}

fn set_leading_bits(bitmap: &mut [u8], count: u64) {
    for bit in 0..count as usize {
        bitmap[bit >> 3] |= 1 << (bit & 7);
    }
}

struct ChunkInfo {
    addr: u64,
    blocks: u32,
    free: u32,
    bitmap_addr: u64,
}

#[allow(clippy::too_many_arguments)]
fn build_spaceman(
    image: &mut Image,
    spaceman_paddr: u64,
    spaceman_oid: u64,
    free_queue_oid: u64,
    cib_base: u64,
    cib_count: u64,
    chunks_per_cib: u64,
    chunk_count: u64,
    blocks_per_chunk: u64,
    ip_base: u64,
    ip_block_count: u64,
    ip_bm_base: u64,
    bitmap_base: u64,
    bitmap_reserve: u64,
    used_final: u64,
    xid: u64,
) -> Result<(), String> {
    let block_count = image.block_count;
    let block_size = image.block_size;

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    let mut bitmap_slot = 0u64;
    for chunk in 0..chunk_count {
        let addr = chunk * blocks_per_chunk;
        let blocks = blocks_per_chunk.min(block_count - addr) as u32;
        if addr >= used_final {
            chunks.push(ChunkInfo {
                addr,
                blocks,
                free: blocks,
                bitmap_addr: 0,
            });
            continue;
        }
        let used_in_chunk = (used_final - addr).min(u64::from(blocks));
        let bitmap_addr = bitmap_base + bitmap_slot;
        bitmap_slot += 1;
        let mut bitmap = vec![0u8; block_size as usize];
        set_leading_bits(&mut bitmap, used_in_chunk);
        image.write_blocks(bitmap_addr, &bitmap);
        chunks.push(ChunkInfo {
            addr,
            blocks,
            free: blocks - used_in_chunk as u32,
            bitmap_addr,
        });
    }
    let recorded_free = block_count - used_final;

    let mut ip_bitmap = vec![0u8; block_size as usize];
    set_leading_bits(&mut ip_bitmap, cib_count + bitmap_slot);
    image.write_blocks(ip_bm_base, &ip_bitmap);

    for cib_index in 0..cib_count {
        let start = (cib_index * chunks_per_cib) as usize;
        let end = (((cib_index + 1) * chunks_per_cib).min(chunk_count)) as usize;
        let mut block = vec![0u8; block_size as usize];
        put_u32(&mut block, 0x20, cib_index as u32);
        put_u32(&mut block, 0x24, (end - start) as u32);
        for (slot, chunk_index) in (start..end).enumerate() {
            let at = 0x28 + slot * CHUNK_INFO_BYTES;
            let chunk = &chunks[chunk_index];
            put_u64(&mut block, at, xid); // ci_xid
            put_u64(&mut block, at + 8, chunk.addr);
            put_u32(&mut block, at + 16, chunk.blocks);
            put_u32(&mut block, at + 20, chunk.free);
            put_u64(&mut block, at + 24, chunk.bitmap_addr);
        }
        let paddr = cib_base + cib_index;
        let sealed = seal(paddr, xid, OBJ_PHYSICAL | TYPE_SPACEMAN_CIB, 0, block);
        image.write_blocks(paddr, &sealed);
    }

    let chunks_per_cab = (u64::from(block_size) - 0x28) / 8;

    let mut sm = vec![0u8; block_size as usize];
    put_u32(&mut sm, 0x20, block_size);
    put_u32(&mut sm, 0x24, blocks_per_chunk as u32);
    put_u32(&mut sm, 0x28, chunks_per_cib as u32);
    put_u32(&mut sm, 0x2C, chunks_per_cab as u32);
    put_u64(&mut sm, 0x30, block_count);
    put_u64(&mut sm, 0x38, chunk_count);
    put_u32(&mut sm, 0x40, cib_count as u32);
    put_u32(&mut sm, 0x44, 0); // sm_cab_count: no chunk-address blocks
    put_u64(&mut sm, 0x48, recorded_free);
    // Each array is 8-byte aligned rather than tight-packed: only the live kernel driver rejects an unaligned ip_bm_free_next_offset.
    fn align8(v: usize) -> usize {
        (v + 7) & !7
    }
    let ring_base = SPACEMAN_STRUCT_SIZE as usize;
    let xid_offset = ring_base;
    let bitmap_offset = align8(xid_offset + IP_RING_LIVE as usize * 8);
    let next_offset = align8(bitmap_offset + IP_RING_LIVE as usize * 2);
    let cib_addr_offset = align8(next_offset + IP_RING_BLOCKS as usize * 2);
    if cib_addr_offset + cib_count as usize * 8 > block_size as usize {
        return Err("space manager ring bookkeeping overflowed its block".into());
    }
    put_u32(&mut sm, 0x50, cib_addr_offset as u32);
    put_u32(
        &mut sm,
        0x60 + 0x20,
        (cib_addr_offset + cib_count as usize * 8) as u32,
    );
    put_u32(&mut sm, 0x90, 1); // sm_flags
    put_u32(&mut sm, 0x94, IP_RING_BLOCKS as u32); // sm_ip_bm_tx_multiplier
    put_u64(&mut sm, 0x98, ip_block_count);
    put_u32(&mut sm, 0xA0, IP_RING_LIVE as u32);
    put_u32(&mut sm, 0xA4, IP_RING_BLOCKS as u32);
    put_u64(&mut sm, 0xA8, ip_bm_base);
    put_u64(&mut sm, 0xB0, ip_base);
    // Only the live kernel driver enforces sm_fq[SFQ_MAIN].sfq_tree_node_limit; fsck_apfs does not look at it.
    let ip_queue = 0xC8;
    let main_queue = 0xC8 + 40;
    put_u16(&mut sm, ip_queue + 24, 1); // sfq_tree_node_limit
    put_u64(&mut sm, main_queue, 0); // sfq_count: nothing pending
    put_u64(&mut sm, main_queue + 8, free_queue_oid);
    let main_node_limit = main_free_queue_node_limit(u64::from(block_size) * block_count)?;
    put_u16(&mut sm, main_queue + 24, main_node_limit); // sfq_tree_node_limit

    put_u16(&mut sm, 0x140, IP_RING_LIVE as u16); // free head
    put_u16(&mut sm, 0x142, (IP_RING_BLOCKS - 1) as u16); // free tail
    put_u32(&mut sm, 0x144, xid_offset as u32);
    put_u32(&mut sm, 0x148, bitmap_offset as u32);
    put_u32(&mut sm, 0x14C, next_offset as u32);
    put_u32(&mut sm, 0x150, 1); // sm_version
    put_u32(&mut sm, 0x154, SPACEMAN_STRUCT_SIZE);

    for slot in 0..IP_RING_LIVE as usize {
        put_u64(&mut sm, xid_offset + slot * 8, xid);
        put_u16(&mut sm, bitmap_offset + slot * 2, slot as u16);
    }
    for slot in 0..IP_RING_BLOCKS as usize {
        let value: u16 = if (slot as u64) < IP_RING_LIVE || slot as u64 == IP_RING_BLOCKS - 1 {
            0xFFFF
        } else {
            (slot + 1) as u16
        };
        put_u16(&mut sm, next_offset + slot * 2, value);
    }
    for index in 0..cib_count {
        put_u64(
            &mut sm,
            cib_addr_offset + index as usize * 8,
            cib_base + index,
        );
    }

    if bitmap_slot > bitmap_reserve {
        return Err(
            "internal: the space manager needed more allocation bitmaps than were reserved".into(),
        );
    }

    let sealed = seal(spaceman_oid, xid, OBJ_EPHEMERAL | TYPE_SPACEMAN, 0, sm);
    image.write_blocks(spaceman_paddr, &sealed);
    let _ = chunks;
    Ok(())
}

fn build_reaper(block_size: u32, oid: u64, xid: u64) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_u32(&mut block, 0x20, 1);
    put_u32(&mut block, 0x40, 1);
    seal(oid, xid, OBJ_EPHEMERAL | TYPE_NX_REAPER, 0, block)
}

const FREE_QUEUE_KEY_BYTES: usize = 16;
const FREE_QUEUE_VALUE_BYTES: usize = 8;

fn build_free_queue_tree(block_size: u32, oid: u64, xid: u64) -> Result<Vec<u8>, String> {
    let leaf = build_fixed_kv_leaf(
        block_size,
        FREE_QUEUE_KEY_BYTES,
        FREE_QUEUE_VALUE_BYTES,
        0xA, // bt_flags: BTREE_EPHEMERAL | BTREE_SEQUENTIAL_INSERT
        &[],
    )?;
    Ok(seal(
        oid,
        xid,
        OBJ_EPHEMERAL | TYPE_BTREE,
        TYPE_SPACEMAN_FREE_QUEUE,
        leaf,
    ))
}

fn build_checkpoint_map(
    block_size: u32,
    oid: u64,
    xid: u64,
    mappings: &[(u32, u32, u64, u64)],
) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_u32(&mut block, 0x20, 1); // cpm_flags: CHECKPOINT_MAP_LAST
    put_u32(&mut block, 0x24, mappings.len() as u32);
    for (index, (o_type, subtype, mapped_oid, paddr)) in mappings.iter().enumerate() {
        let at = 0x28 + index * CHECKPOINT_MAPPING_BYTES;
        put_u32(&mut block, at, *o_type);
        put_u32(&mut block, at + 4, *subtype);
        put_u32(&mut block, at + 8, block_size); // cpm_size: one block, like every mapped object here
        put_u32(&mut block, at + 12, 0); // cpm_pad
        put_u64(&mut block, at + 16, 0); // cpm_fs_oid: none of these belong to a volume
        put_u64(&mut block, at + 24, *mapped_oid);
        put_u64(&mut block, at + 32, *paddr);
    }
    seal(oid, xid, OBJ_PHYSICAL | TYPE_CHECKPOINT_MAP, 0, block)
}

#[allow(clippy::too_many_arguments)]
fn build_nxsb(
    block_size: u32,
    block_count: u64,
    uuid: [u8; 16],
    next_oid: u64,
    descriptor_base: u64,
    data_base: u64,
    desc_ring_blocks: u32,
    data_ring_blocks: u32,
    eph_min_block_count: u64,
    spaceman_oid: u64,
    container_omap_paddr: u64,
    reaper_oid: u64,
    volume_oids: &[u64],
    xid: u64,
) -> Vec<u8> {
    let mut block = vec![0u8; block_size as usize];
    put_u32(&mut block, 0x20, NX_MAGIC);
    put_u32(&mut block, 0x24, block_size);
    put_u64(&mut block, 0x28, block_count);
    put_u64(&mut block, 0x30, 0); // features
    put_u64(&mut block, 0x38, 0); // read-only compatible features
    put_u64(&mut block, 0x40, 0x2);
    block[0x48..0x58].copy_from_slice(&uuid);
    put_u64(&mut block, 0x58, next_oid);
    put_u64(&mut block, 0x60, xid + 1); // next_xid
    put_u32(&mut block, 0x68, desc_ring_blocks); // xp_desc_blocks
    put_u32(&mut block, 0x6C, data_ring_blocks); // xp_data_blocks
    put_u64(&mut block, 0x70, descriptor_base);
    put_u64(&mut block, 0x78, data_base);
    put_u32(&mut block, 0x80, 2); // xp_desc_next
    put_u32(&mut block, 0x84, 3); // xp_data_next
    put_u32(&mut block, 0x88, 0); // xp_desc_index
    put_u32(&mut block, 0x8C, 2); // xp_desc_len: NXSB, checkpoint map
    put_u32(&mut block, 0x90, 0); // xp_data_index
    put_u32(&mut block, 0x94, 3); // xp_data_len: spaceman, reaper, free queue
    put_u64(&mut block, 0x98, spaceman_oid);
    put_u64(&mut block, 0xA0, container_omap_paddr);
    put_u64(&mut block, 0xA8, reaper_oid);
    let container_bytes = block_count * u64::from(block_size);
    let max_file_systems = (container_bytes / (512 * 1024 * 1024)).clamp(1, 100);
    put_u32(&mut block, 0xB4, max_file_systems as u32);
    for (index, oid) in volume_oids.iter().enumerate() {
        put_u64(&mut block, 0xB8 + index * 8, *oid);
    }
    put_u64(
        &mut block,
        0x520,
        (eph_min_block_count << 32) | (4u64 << 16) | 1,
    );
    seal(1, xid, OBJ_EPHEMERAL | TYPE_NX_SUPERBLOCK, 0, block)
}

fn validated_group(bytes: [u8; 16]) -> String {
    format_uuid(&bytes)
}

pub fn create(part_bytes: u64, os_name: &str, stage1: &[u8]) -> Result<Vec<u8>, String> {
    create_with_system_version(part_bytes, os_name, stage1, None)
}

pub(crate) fn validate_system_version(bytes: &[u8]) -> Result<(), String> {
    let value =
        plist::Value::from_reader(std::io::Cursor::new(bytes)).map_err(|e| e.to_string())?;
    let dictionary = value
        .as_dictionary()
        .ok_or("SystemVersion must be a dictionary")?;
    for key in ["ProductName", "ProductVersion", "ProductBuildVersion"] {
        if dictionary
            .get(key)
            .and_then(plist::Value::as_string)
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(format!("SystemVersion lacks nonempty {key}"));
        }
    }
    if dictionary
        .get("ProductUserVisibleVersion")
        .is_some_and(|value| value.as_string().is_none_or(|text| text.trim().is_empty()))
    {
        return Err("invalid ProductUserVisibleVersion".into());
    }
    Ok(())
}

pub fn create_with_system_version(
    part_bytes: u64,
    os_name: &str,
    stage1: &[u8],
    system_version: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    create_with_preboot_files(part_bytes, os_name, stage1, system_version, &[], &[])
}

fn validate_payload_paths(
    files: &[(String, Vec<u8>)],
    reserved: &[&str],
    system_version: Option<&[u8]>,
) -> Result<(), String> {
    let mut paths = std::collections::BTreeSet::new();
    for path in reserved {
        paths.insert(path.to_ascii_lowercase());
    }
    let mut supplied = std::collections::BTreeSet::new();
    for (path, bytes) in files {
        if path.split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || part.len() > 255
                || !part.is_ascii()
                || part
                    .chars()
                    .any(|c| c.is_control() || c == '\\' || c == ':')
        }) {
            return Err(format!("invalid relative APFS payload path: {path}"));
        }
        let normalized = path.to_ascii_lowercase();
        if !supplied.insert(normalized.clone()) {
            return Err(format!("duplicate APFS payload path: {path}"));
        }
        if matches!(
            normalized.as_str(),
            "systemversion.plist" | "restore/systemversion.plist"
        ) && system_version == Some(bytes.as_slice())
        {
            continue;
        }
        if paths.iter().any(|old| {
            old == &normalized
                || old.starts_with(&format!("{normalized}/"))
                || normalized.starts_with(&format!("{old}/"))
        }) {
            return Err(format!("colliding APFS payload path: {path}"));
        }
        paths.insert(normalized);
    }
    Ok(())
}

pub(crate) fn preboot_metadata_path<'a>(
    files: &'a [(String, Vec<u8>)],
    canonical: &'a str,
) -> &'a str {
    files
        .iter()
        .find(|(path, _)| path.eq_ignore_ascii_case(canonical))
        .map(|(path, _)| path.as_str())
        .unwrap_or(canonical)
}

pub(crate) fn validate_preboot_files(
    files: &[(String, Vec<u8>)],
    system_version: Option<&[u8]>,
) -> Result<(), String> {
    validate_payload_paths(
        files,
        &[
            "boot.bin",
            "SystemVersion.plist",
            "restore/SystemVersion.plist",
        ],
        system_version,
    )
}

pub(crate) fn validate_system_files(files: &[(String, Vec<u8>)]) -> Result<(), String> {
    validate_payload_paths(
        files,
        &[
            "System/Library/CoreServices/SystemVersion.plist",
            "Finish Installation.app/Contents/Resources/boot.bin",
        ],
        None,
    )
}

pub fn create_with_preboot_files(
    part_bytes: u64,
    os_name: &str,
    stage1: &[u8],
    system_version: Option<&[u8]>,
    preboot_files: &[(String, Vec<u8>)],
    system_files: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    validate_preboot_files(preboot_files, system_version)?;
    validate_system_files(system_files)?;
    if stage1.is_empty() {
        return Err("Stage-one boot object is empty".into());
    }
    if part_bytes == 0 || !part_bytes.is_multiple_of(u64::from(APFS_BLOCK)) {
        return Err("APFS container size must be a nonzero multiple of 4096 bytes".into());
    }
    let block_size = APFS_BLOCK;
    let block_count = part_bytes / u64::from(block_size);
    let xid = 1u64;

    let (desc_ring_blocks, data_ring_blocks, eph_min_block_count) =
        checkpoint_geometry(part_bytes)?;
    let desc_ring_blocks_u64 = u64::from(desc_ring_blocks);
    let data_ring_blocks_u64 = u64::from(data_ring_blocks);

    let plist_bytes = match system_version {
        Some(bytes) => {
            validate_system_version(bytes)?;
            bytes.to_vec()
        }
        None => system_version_plist(os_name)?,
    };
    let group_bytes = random16()?;
    let group = validated_group(group_bytes);

    let mut image = Image::new(block_size, block_count);

    let block_zero_paddr = image.alloc(1)?;
    let descriptor_base = image.alloc(desc_ring_blocks_u64)?;
    let cpmap_paddr = descriptor_base;
    let nxsb_paddr = descriptor_base + 1;
    let data_base = image.alloc(data_ring_blocks_u64)?;
    let spaceman_paddr = data_base;
    let reaper_paddr = data_base + 1;
    let free_queue_paddr = data_base + 2;
    debug_assert_eq!(block_zero_paddr, 0);
    debug_assert_eq!(descriptor_base, 1);
    debug_assert_eq!(data_base, descriptor_base + desc_ring_blocks_u64);

    let blocks_per_chunk = u64::from(block_size) * 8;
    let chunks_per_cib = (u64::from(block_size) - 0x28) / CHUNK_INFO_BYTES as u64;
    let chunk_count = block_count.div_ceil(blocks_per_chunk);
    let cib_count = chunk_count.div_ceil(chunks_per_cib);

    let ip_bm_base = image.alloc(IP_RING_BLOCKS)?;

    let mut next_oid = 0x400u64;
    let take_oid = |next_oid: &mut u64| {
        let oid = *next_oid;
        *next_oid += 1;
        oid
    };
    let spaceman_oid = take_oid(&mut next_oid);
    let reaper_oid = take_oid(&mut next_oid);
    let free_queue_oid = take_oid(&mut next_oid);

    let (data_oid, data_paddr) = build_volume(
        &mut image,
        &mut next_oid,
        0,
        &format!("{os_name} Data"),
        APFS_VOL_ROLE_DATA,
        group_bytes,
        xid,
        None,
        |_fs| Ok(()),
    )?;

    let snapshot_name = format!("{os_name} install");
    let (system_oid, system_paddr) = build_volume(
        &mut image,
        &mut next_oid,
        1,
        os_name,
        APFS_VOL_ROLE_SYSTEM,
        group_bytes,
        xid,
        Some(snapshot_name.as_str()),
        |fs| {
            fs.add_file(
                &["System", "Library", "CoreServices"],
                "SystemVersion.plist",
                &plist_bytes,
            )?;
            fs.add_file(
                &["Finish Installation.app", "Contents", "Resources"],
                "boot.bin",
                stage1,
            )?;
            for (path, data) in system_files {
                let mut parts: Vec<_> = path.split('/').collect();
                let name = parts.pop().ok_or("empty System path")?;
                fs.add_file(&parts, name, data)?;
            }
            Ok(())
        },
    )?;

    let (preboot_oid, preboot_paddr) = build_volume(
        &mut image,
        &mut next_oid,
        2,
        "Preboot",
        APFS_VOL_ROLE_PREBOOT,
        [0u8; 16],
        xid,
        None,
        |fs| {
            let g = group.as_str();
            fs.add_file(&[g], "boot.bin", stage1)?;
            for canonical in ["SystemVersion.plist", "restore/SystemVersion.plist"] {
                let mut parts = vec![g];
                parts.extend(preboot_metadata_path(preboot_files, canonical).split('/'));
                let name = parts.pop().ok_or("empty metadata path")?;
                fs.add_file(&parts, name, &plist_bytes)?;
            }
            fs.add_file(&[], "boot-volume", format!("{group}\n").as_bytes())?;
            for (path, data) in preboot_files {
                if path.eq_ignore_ascii_case("SystemVersion.plist")
                    || path.eq_ignore_ascii_case("restore/SystemVersion.plist")
                {
                    continue;
                }
                let mut parts = vec![g];
                parts.extend(path.split('/'));
                let name = parts.pop().ok_or("empty Preboot path")?;
                fs.add_file(&parts, name, data)?;
            }
            Ok(())
        },
    )?;

    let (recovery_oid, recovery_paddr) = build_volume(
        &mut image,
        &mut next_oid,
        3,
        "Recovery",
        APFS_VOL_ROLE_RECOVERY,
        [0u8; 16],
        xid,
        None,
        |_fs| Ok(()),
    )?;

    let volumes = [
        (data_oid, data_paddr),
        (system_oid, system_paddr),
        (preboot_oid, preboot_paddr),
        (recovery_oid, recovery_paddr),
    ];

    let entries: Vec<(Vec<u8>, Vec<u8>)> = volumes
        .iter()
        .map(|(oid, paddr)| omap_kv(*oid, xid, *paddr, block_size))
        .collect();
    let container_tree = build_omap_leaf(block_size, &entries)?;
    let container_omap_tree_paddr = image.alloc(1)?;
    let sealed_tree = seal(
        container_omap_tree_paddr,
        xid,
        OBJ_PHYSICAL | TYPE_BTREE,
        TYPE_OMAP,
        container_tree,
    );
    image.write_blocks(container_omap_tree_paddr, &sealed_tree);

    let container_omap_paddr = image.alloc(1)?;
    let comap_block = build_omap_phys(block_size, container_omap_tree_paddr, 1, 0, 0, 0);
    let sealed_comap = seal(
        container_omap_paddr,
        xid,
        OBJ_PHYSICAL | TYPE_OMAP,
        0,
        comap_block,
    );
    image.write_blocks(container_omap_paddr, &sealed_comap);

    let base_used = image.next;
    let touched_needed = base_used.div_ceil(blocks_per_chunk).max(1);
    let bitmap_reserve = touched_needed + 1;
    let ip_block_count = (cib_count + bitmap_reserve).max(3 * chunk_count + 3);
    let ip_base = image.alloc(ip_block_count)?;
    let cib_base = ip_base;
    let bitmap_base = ip_base + cib_count;
    let used_final = image.next;

    build_spaceman(
        &mut image,
        spaceman_paddr,
        spaceman_oid,
        free_queue_oid,
        cib_base,
        cib_count,
        chunks_per_cib,
        chunk_count,
        blocks_per_chunk,
        ip_base,
        ip_block_count,
        ip_bm_base,
        bitmap_base,
        bitmap_reserve,
        used_final,
        xid,
    )?;

    let sealed_reaper = build_reaper(block_size, reaper_oid, xid);
    image.write_blocks(reaper_paddr, &sealed_reaper);

    let sealed_free_queue = build_free_queue_tree(block_size, free_queue_oid, xid)?;
    image.write_blocks(free_queue_paddr, &sealed_free_queue);

    let mappings = [
        (
            OBJ_EPHEMERAL | TYPE_SPACEMAN,
            0u32,
            spaceman_oid,
            spaceman_paddr,
        ),
        (
            OBJ_EPHEMERAL | TYPE_NX_REAPER,
            0u32,
            reaper_oid,
            reaper_paddr,
        ),
        (
            OBJ_EPHEMERAL | TYPE_BTREE,
            TYPE_SPACEMAN_FREE_QUEUE,
            free_queue_oid,
            free_queue_paddr,
        ),
    ];
    let sealed_cpmap = build_checkpoint_map(block_size, cpmap_paddr, xid, &mappings);
    image.write_blocks(cpmap_paddr, &sealed_cpmap);

    let nx_uuid = random16()?;
    let volume_oids: Vec<u64> = volumes.iter().map(|(oid, _)| *oid).collect();
    let sealed_nxsb = build_nxsb(
        block_size,
        block_count,
        nx_uuid,
        next_oid,
        descriptor_base,
        data_base,
        desc_ring_blocks,
        data_ring_blocks,
        eph_min_block_count,
        spaceman_oid,
        container_omap_paddr,
        reaper_oid,
        &volume_oids,
        xid,
    );
    image.write_blocks(block_zero_paddr, &sealed_nxsb);
    image.write_blocks(nxsb_paddr, &sealed_nxsb);

    Ok(image.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_read::{ApfsContainer, VolumeChoice};
    use crate::apfs_verify::{SliceBlocks, verify_container};

    const OS_NAME: &str = "Test Linux";
    const MULTI_VOLUME_CONTAINER_BYTES: u64 = 2560 * 1024 * 1024;

    fn read_whole(bytes: &[u8], block_size: u32, path: &str, volume: &str) -> Vec<u8> {
        let block_count = bytes.len() as u64 / u64::from(block_size);
        let mut blocks = SliceBlocks::new(bytes, block_size);
        let mut container = ApfsContainer::mount(&mut blocks, block_size, block_count)
            .expect("mount the container this writer just built");
        let mounted = container
            .open_volume_chosen(&VolumeChoice::Named(volume.to_string()))
            .unwrap_or_else(|e| panic!("open volume {volume:?}: {e}"));
        let mut out = Vec::new();
        container
            .extract(&mounted, path, 0, None, &mut out)
            .unwrap_or_else(|e| panic!("extract {path:?} from {volume:?}: {e}"));
        out
    }

    #[test]
    fn multi_level_fixed_tree_round_trips_all_mappings() {
        let mut image = Image::new(APFS_BLOCK, 1024);
        image.alloc(1).unwrap();
        let count = 20_000u64;
        let records = (1..=count)
            .map(|oid| omap_kv(oid, 7, oid + 100, APFS_BLOCK))
            .collect();
        let (root, _) = write_tree(
            &mut image,
            records,
            TreeLayout {
                fixed: Some((16, 16)),
                flags: 0x12,
                subtype: TYPE_OMAP,
            },
            7,
            None,
            &mut 1,
        )
        .unwrap();
        let root_at = root as usize * APFS_BLOCK as usize;
        assert!(
            u16::from_le_bytes(
                image.bytes[root_at + 0x22..root_at + 0x24]
                    .try_into()
                    .unwrap()
            ) >= 2
        );
        let mut source = SliceBlocks::new(&image.bytes, APFS_BLOCK);
        let mut verifier = crate::apfs_verify::Verifier {
            source: &mut source,
            block_size: APFS_BLOCK as usize,
            block_count: image.block_count,
            objects_checked: 0,
            in_use: Vec::new(),
        };
        let mut entries = verifier.collect_omap(root, "synthetic object map").unwrap();
        entries.sort_by_key(|entry| entry.oid);
        assert_eq!(entries.len(), count as usize);
        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                (entry.oid, entry.xid, entry.paddr),
                (i as u64 + 1, 7, i as u64 + 101)
            );
        }
    }

    #[test]
    fn multi_node_volume_round_trips_and_verifies() {
        let files: Vec<_> = (0..300)
            .map(|i| {
                (
                    format!("usr/firmware/group{}/asset-{i:04}.bin", i % 11),
                    format!("firmware-{i}").into_bytes(),
                )
            })
            .collect();
        let image = create_with_preboot_files(
            MULTI_VOLUME_CONTAINER_BYTES,
            OS_NAME,
            &[1, 2, 3],
            None,
            &[],
            &files,
        )
        .expect("create multi-node volume");
        verify_container(&mut SliceBlocks::new(&image, APFS_BLOCK))
            .expect("verify multi-node volume");
        for i in [0, 127, 299] {
            assert_eq!(
                read_whole(&image, APFS_BLOCK, &format!("/{}", files[i].0), OS_NAME),
                files[i].1
            );
        }
    }

    #[test]
    fn rejects_empty_stage1() {
        assert!(create(16 * 1024 * 1024, OS_NAME, &[]).is_err());
    }

    #[test]
    fn rejects_a_size_that_is_not_a_multiple_of_the_block_size() {
        assert!(create(16 * 1024 * 1024 + 1, OS_NAME, &[0xAB]).is_err());
    }

    #[test]
    fn rejects_a_container_too_small_to_hold_its_own_structures() {
        assert!(create(64 * 1024, OS_NAME, &[0xAB; 4096]).is_err());
    }

    #[test]
    fn creates_a_container_that_passes_independent_verification() {
        let stage1 = vec![0xA5u8; 200_003];
        let image = create(MULTI_VOLUME_CONTAINER_BYTES, OS_NAME, &stage1).expect("create");
        assert_eq!(image.len(), MULTI_VOLUME_CONTAINER_BYTES as usize);

        let mut blocks = SliceBlocks::new(&image, APFS_BLOCK);
        let verified = verify_container(&mut blocks).expect("verify_container");
        assert_eq!(verified.block_size, APFS_BLOCK);
        assert_eq!(verified.volumes.len(), 4);
        assert!(verified.free_block_count > 0);
        assert!(verified.free_block_count < verified.block_count);
    }

    #[test]
    fn system_volume_can_carry_a_real_snapshot_the_reader_walks() {
        let stage1 = vec![0x77u8; 4096];
        let image = create(MULTI_VOLUME_CONTAINER_BYTES, OS_NAME, &stage1).expect("create");
        let block_count = image.len() as u64 / u64::from(APFS_BLOCK);
        let mut blocks = SliceBlocks::new(&image, APFS_BLOCK);
        let mut container =
            ApfsContainer::mount(&mut blocks, APFS_BLOCK, block_count).expect("mount");
        let summaries = container.volumes().expect("list volumes");
        let system_summary = summaries
            .iter()
            .find(|summary| summary.name == OS_NAME)
            .expect("System volume summary");
        assert_eq!(system_summary.declared_snapshots, 1);

        let system = container
            .open_volume_chosen(&VolumeChoice::Named(OS_NAME.to_string()))
            .expect("open the System volume");

        let snapshots = container
            .snapshots(&system)
            .expect("read the System volume's snapshots");
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(snapshot.name, format!("{OS_NAME} install"));
        assert_ne!(snapshot.sblock_oid, 0);
        assert_ne!(snapshot.extentref_tree_oid, 0);

        let mounted_snapshot = container
            .open_snapshot(&system, &snapshot.name)
            .expect("open the snapshot this writer took");
        assert_eq!(
            mounted_snapshot.snapshot().map(|s| s.xid),
            Some(snapshot.xid)
        );
        let mut out = Vec::new();
        container
            .extract(
                &mounted_snapshot,
                "/System/Library/CoreServices/SystemVersion.plist",
                0,
                None,
                &mut out,
            )
            .expect("extract SystemVersion.plist through the snapshot");
        assert_eq!(out, system_version_plist(OS_NAME).expect("plist"));
    }

    #[test]
    fn only_the_system_volume_takes_a_snapshot() {
        let stage1 = vec![0x11u8; 4096];
        let image = create(MULTI_VOLUME_CONTAINER_BYTES, OS_NAME, &stage1).expect("create");
        let block_count = image.len() as u64 / u64::from(APFS_BLOCK);
        let mut blocks = SliceBlocks::new(&image, APFS_BLOCK);
        let mut container =
            ApfsContainer::mount(&mut blocks, APFS_BLOCK, block_count).expect("mount");
        let summaries = container.volumes().expect("list volumes");
        for name in ["Preboot", "Recovery", &format!("{OS_NAME} Data")] {
            let summary = summaries
                .iter()
                .find(|summary| summary.name == name)
                .unwrap_or_else(|| panic!("{name:?} summary"));
            assert_eq!(summary.declared_snapshots, 0);
            let volume = container
                .open_volume_chosen(&VolumeChoice::Named(name.to_string()))
                .unwrap_or_else(|e| panic!("open {name:?}: {e}"));
            let snapshots = container
                .snapshots(&volume)
                .unwrap_or_else(|e| panic!("read {name:?}'s snapshots: {e}"));
            assert!(snapshots.is_empty());
        }
    }

    #[test]
    fn round_trips_every_file_the_original_native_writer_wrote() {
        let stage1 = vec![0x5Au8; 133_121];
        let image = create(MULTI_VOLUME_CONTAINER_BYTES, OS_NAME, &stage1).expect("create");

        let expected_plist = system_version_plist(OS_NAME).expect("plist");

        assert_eq!(
            read_whole(
                &image,
                APFS_BLOCK,
                "/System/Library/CoreServices/SystemVersion.plist",
                OS_NAME,
            ),
            expected_plist
        );
        assert_eq!(
            read_whole(
                &image,
                APFS_BLOCK,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME,
            ),
            stage1
        );

        let selector = read_whole(&image, APFS_BLOCK, "/boot-volume", "Preboot");
        let selector = String::from_utf8(selector).expect("boot-volume is UTF-8");
        let group = selector.trim().to_string();
        assert_eq!(group.len(), 36, "{group:?} is not a 36-character uuid");
        assert_eq!(group, group.to_ascii_lowercase());

        assert_eq!(
            read_whole(&image, APFS_BLOCK, &format!("/{group}/boot.bin"), "Preboot"),
            stage1
        );
        assert_eq!(
            read_whole(
                &image,
                APFS_BLOCK,
                &format!("/{group}/SystemVersion.plist"),
                "Preboot",
            ),
            expected_plist
        );
        assert_eq!(
            read_whole(
                &image,
                APFS_BLOCK,
                &format!("/{group}/restore/SystemVersion.plist"),
                "Preboot",
            ),
            expected_plist
        );

        let block_count = image.len() as u64 / u64::from(APFS_BLOCK);
        let mut blocks = SliceBlocks::new(&image, APFS_BLOCK);
        let mut container =
            ApfsContainer::mount(&mut blocks, APFS_BLOCK, block_count).expect("mount");
        let summaries = container.volumes().expect("volumes");
        assert_eq!(summaries.len(), 4);
        let data = summaries
            .iter()
            .find(|v| v.name == format!("{OS_NAME} Data"))
            .expect("Data volume");
        assert_eq!(data.role, APFS_VOL_ROLE_DATA);
        let system = summaries
            .iter()
            .find(|v| v.name == OS_NAME)
            .expect("System volume");
        assert_eq!(system.role, APFS_VOL_ROLE_SYSTEM);
        assert_eq!(system.volume_group_id, data.volume_group_id);
        assert_ne!(system.volume_group_id, [0u8; 16]);
        let preboot = summaries
            .iter()
            .find(|v| v.name == "Preboot")
            .expect("Preboot volume");
        assert_eq!(preboot.role, APFS_VOL_ROLE_PREBOOT);
        let recovery = summaries
            .iter()
            .find(|v| v.name == "Recovery")
            .expect("Recovery volume");
        assert_eq!(recovery.role, APFS_VOL_ROLE_RECOVERY);
    }

    #[test]
    fn every_reserved_and_written_block_is_reachable_and_allocated() {
        let stage1 = vec![0x11u8; 4097];
        let image = create(MULTI_VOLUME_CONTAINER_BYTES, OS_NAME, &stage1).expect("create");
        let mut blocks = SliceBlocks::new(&image, APFS_BLOCK);
        verify_container(&mut blocks).expect("verify_container");
        assert_eq!(
            read_whole(
                &image,
                APFS_BLOCK,
                "/Finish Installation.app/Contents/Resources/boot.bin",
                OS_NAME,
            ),
            stage1
        );
    }
}
