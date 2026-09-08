use std::path::Path;

use crate::apfs_image::{
    APFS_VOL_ROLE_NONE, APPLE_APFS_TYPE_GUID, GPT_SIGNATURE, NX_MAGIC, SECTOR_BYTES,
    fletcher64_seal, gpt_first_usable_lba, gpt_reserved_blocks, guid,
};
use crate::crypto::embedded_panic_crc32;

pub const FIXTURE_VOLUME: &str = "Explorer";
pub const FIXTURE_DIR: &str = "docs";
pub const FIXTURE_FILE: &str = "readme.txt";
pub const FIXTURE_FILE_BYTES: &[u8] = b"hello-apfs-explorer";
pub const FIXTURE_SYMLINK: &str = "link";
pub const FIXTURE_SYMLINK_TARGET: &str = "readme.txt";
pub const FIXTURE_NESTED: &str = "nested";
pub const FIXTURE_NESTED_FILE: &str = "note.txt";
pub const FIXTURE_NESTED_BYTES: &[u8] = b"nested-ok";
pub const FIXTURE_VOL_APSB_PADDR: u64 = VOL_APSB;

const APFS_BLOCK: u32 = 4096;
const TYPE_NX_SUPERBLOCK: u32 = 0x01;
const TYPE_BTREE: u32 = 0x02;
const TYPE_OMAP: u32 = 0x0B;
const TYPE_FS: u32 = 0x0D;
const OBJ_PHYSICAL: u32 = 0x4000_0000;
const OBJ_VIRTUAL: u32 = 0x0000_0000;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;
const APFS_MAGIC: u32 = 0x4253_5041;
const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;
const J_INODE: u64 = 3;
const J_FILE_EXTENT: u64 = 8;
const J_DIR_REC: u64 = 9;
const S_IFDIR: u16 = 0x4000;
const S_IFREG: u16 = 0x8000;
const S_IFLNK: u16 = 0xA000;
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;
const INODE_XFIELDS_OFFSET: usize = 0x5C;
const INO_EXT_TYPE_DSTREAM: u8 = 8;
const DSTREAM_BYTES: usize = 40;

const ROOT_INO: u64 = 2;
const DOCS_INO: u64 = 16;
const FILE_INO: u64 = 17;
const LINK_INO: u64 = 18;
const NESTED_INO: u64 = 19;
const NOTE_INO: u64 = 20;

const OMAP_C: u64 = 17;
const OMAP_TREE_C: u64 = 18;
const VOL_OMAP: u64 = 19;
const VOL_OMAP_TREE: u64 = 20;
const VOL_APSB: u64 = 21;
const VOL_FS: u64 = 22;
const FILE_DATA_BLK: u64 = 23;
const LINK_DATA_BLK: u64 = 24;
const NOTE_DATA_BLK: u64 = 25;
const BLOCK_COUNT: u64 = 64;
const VOL_OID: u64 = 1024;
const FS_OID: u64 = 2048;
const XID: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageWrap {
    RawGpt,
    Qcow2,
    Dmg,
}

pub fn write_fixture(path: &Path, wrap: ImageWrap) -> Result<(), String> {
    let gpt = gpt_disk();
    match wrap {
        ImageWrap::RawGpt => std::fs::write(path, gpt).map_err(|e| e.to_string()),
        ImageWrap::Qcow2 => {
            crate::asahi_ops::write_qcow2_image(path, gpt.len() as u64, &[(0, gpt)])
                .map_err(|e| e.to_string())
        }
        ImageWrap::Dmg => {
            let dmg = wrap_udif(&gpt)?;
            std::fs::write(path, dmg).map_err(|e| e.to_string())
        }
    }
}

pub fn container_bytes() -> Vec<u8> {
    let mut image = vec![0u8; (BLOCK_COUNT * u64::from(APFS_BLOCK)) as usize];
    let put = |image: &mut [u8], paddr: u64, block: &[u8]| {
        let at = (paddr * u64::from(APFS_BLOCK)) as usize;
        image[at..at + block.len()].copy_from_slice(block);
    };

    let nx_uuid = guid(
        0x4E58_0001,
        0x1111,
        0x2222,
        [0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
    );
    let vol_uuid = guid(
        0x564F_4C01,
        0x1111,
        0x2222,
        [0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA],
    );

    let nxsb = write_nxsb(BLOCK_COUNT, nx_uuid, OMAP_C, &[VOL_OID], XID, 1);
    put(&mut image, 0, &nxsb);
    let mut nxsb_cp = write_nxsb(BLOCK_COUNT, nx_uuid, OMAP_C, &[VOL_OID], XID, 1);
    obj_stamp(&mut nxsb_cp, 1, XID, TYPE_NX_SUPERBLOCK | OBJ_EPHEMERAL, 0);
    put(&mut image, 1, &nxsb_cp);

    let cont_omap_recs = vec![omap_record(VOL_OID, XID, VOL_APSB)];
    let mut cont_tree = btree_leaf(APFS_BLOCK as usize, &cont_omap_recs, true);
    obj_stamp(
        &mut cont_tree,
        OMAP_TREE_C,
        XID,
        TYPE_BTREE | OBJ_PHYSICAL,
        TYPE_OMAP,
    );
    put(&mut image, OMAP_TREE_C, &cont_tree);
    put(&mut image, OMAP_C, &write_omap(OMAP_TREE_C, XID, OMAP_C));

    let vol_omap_recs = vec![omap_record(FS_OID, XID, VOL_FS)];
    let mut vol_tree = btree_leaf(APFS_BLOCK as usize, &vol_omap_recs, true);
    obj_stamp(
        &mut vol_tree,
        VOL_OMAP_TREE,
        XID,
        TYPE_BTREE | OBJ_PHYSICAL,
        TYPE_OMAP,
    );
    put(&mut image, VOL_OMAP_TREE, &vol_tree);
    put(
        &mut image,
        VOL_OMAP,
        &write_omap(VOL_OMAP_TREE, XID, VOL_OMAP),
    );

    let apsb = write_apsb(
        FIXTURE_VOLUME,
        APFS_VOL_ROLE_NONE,
        vol_uuid,
        VOL_OMAP,
        FS_OID,
        XID,
        VOL_OID,
    );
    put(&mut image, VOL_APSB, &apsb);

    let fs_records = vec![
        (
            inode_key(ROOT_INO),
            inode_val(1, ROOT_INO, S_IFDIR | 0o755, 1, None),
        ),
        (drec_key(ROOT_INO, FIXTURE_DIR), drec_val(DOCS_INO, DT_DIR)),
        (
            inode_key(DOCS_INO),
            inode_val(ROOT_INO, DOCS_INO, S_IFDIR | 0o755, 3, None),
        ),
        (
            drec_key(DOCS_INO, FIXTURE_SYMLINK),
            drec_val(LINK_INO, DT_LNK),
        ),
        (
            drec_key(DOCS_INO, FIXTURE_NESTED),
            drec_val(NESTED_INO, DT_DIR),
        ),
        (drec_key(DOCS_INO, FIXTURE_FILE), drec_val(FILE_INO, DT_REG)),
        (
            inode_key(FILE_INO),
            inode_val(
                DOCS_INO,
                FILE_INO,
                S_IFREG | 0o644,
                1,
                Some(FIXTURE_FILE_BYTES.len() as u64),
            ),
        ),
        (
            extent_key(FILE_INO, 0),
            extent_val(u64::from(APFS_BLOCK), FILE_DATA_BLK),
        ),
        (
            inode_key(LINK_INO),
            inode_val(
                DOCS_INO,
                LINK_INO,
                S_IFLNK | 0o777,
                1,
                Some(FIXTURE_SYMLINK_TARGET.len() as u64),
            ),
        ),
        (
            extent_key(LINK_INO, 0),
            extent_val(u64::from(APFS_BLOCK), LINK_DATA_BLK),
        ),
        (
            inode_key(NESTED_INO),
            inode_val(DOCS_INO, NESTED_INO, S_IFDIR | 0o755, 1, None),
        ),
        (
            drec_key(NESTED_INO, FIXTURE_NESTED_FILE),
            drec_val(NOTE_INO, DT_REG),
        ),
        (
            inode_key(NOTE_INO),
            inode_val(
                NESTED_INO,
                NOTE_INO,
                S_IFREG | 0o644,
                1,
                Some(FIXTURE_NESTED_BYTES.len() as u64),
            ),
        ),
        (
            extent_key(NOTE_INO, 0),
            extent_val(u64::from(APFS_BLOCK), NOTE_DATA_BLK),
        ),
    ];

    let mut fs = btree_leaf(APFS_BLOCK as usize, &fs_records, true);
    obj_stamp(&mut fs, VOL_FS, XID, TYPE_BTREE | OBJ_PHYSICAL, 0);
    put(&mut image, VOL_FS, &fs);

    let file_at = (FILE_DATA_BLK * u64::from(APFS_BLOCK)) as usize;
    image[file_at..file_at + FIXTURE_FILE_BYTES.len()].copy_from_slice(FIXTURE_FILE_BYTES);
    let link_at = (LINK_DATA_BLK * u64::from(APFS_BLOCK)) as usize;
    image[link_at..link_at + FIXTURE_SYMLINK_TARGET.len()]
        .copy_from_slice(FIXTURE_SYMLINK_TARGET.as_bytes());
    let note_at = (NOTE_DATA_BLK * u64::from(APFS_BLOCK)) as usize;
    image[note_at..note_at + FIXTURE_NESTED_BYTES.len()].copy_from_slice(FIXTURE_NESTED_BYTES);

    image
}

pub fn gpt_disk() -> Vec<u8> {
    let payload = container_bytes();
    wrap_gpt(&payload)
}

pub fn wrap_gpt(payload: &[u8]) -> Vec<u8> {
    let sector = SECTOR_BYTES as u32;
    let part_sectors = (payload.len() as u64).div_ceil(u64::from(sector)).max(1);
    let first_lba = 40u64;
    let last_lba_part = first_lba + part_sectors - 1;
    let backup_header = last_lba_part + gpt_reserved_blocks(sector);
    let disk_sectors = backup_header + 1;
    let mut image = vec![0u8; (disk_sectors * u64::from(sector)) as usize];

    let mut mbr = vec![0u8; SECTOR_BYTES];
    mbr[0x1BE + 4] = 0xEE;
    mbr[0x1BE + 8] = 1;
    let mbr_sectors = (backup_header as u32).saturating_sub(1);
    mbr[0x1BE + 12..0x1BE + 16].copy_from_slice(&mbr_sectors.to_le_bytes());
    mbr[0x1FE] = 0x55;
    mbr[0x1FF] = 0xAA;
    image[0..SECTOR_BYTES].copy_from_slice(&mbr);

    let disk_guid = guid(0x4449_534B, 0x0001, 0x4000, [0x80, 1, 2, 3, 4, 5, 6, 7]);
    let part_guid = guid(0x4150_4653, 0x0001, 0x4000, [0x80, 9, 8, 7, 6, 5, 4, 3]);
    let mut array = vec![0u8; 128 * 128];
    array[0..16].copy_from_slice(&APPLE_APFS_TYPE_GUID);
    array[16..32].copy_from_slice(&part_guid);
    array[32..40].copy_from_slice(&first_lba.to_le_bytes());
    array[40..48].copy_from_slice(&last_lba_part.to_le_bytes());
    let name = utf16le_name("APFS");
    array[56..128].copy_from_slice(&name);
    let array_crc = embedded_panic_crc32(&array);
    let array_at = 2 * SECTOR_BYTES;
    image[array_at..array_at + array.len()].copy_from_slice(&array);

    let write_header = |current: u64, alt: u64, part_lba: u64| -> Vec<u8> {
        let mut h = vec![0u8; SECTOR_BYTES];
        h[0..8].copy_from_slice(&GPT_SIGNATURE);
        put_u32(&mut h, 8, 0x0001_0000);
        put_u32(&mut h, 12, 92);
        put_u64(&mut h, 24, current);
        put_u64(&mut h, 32, alt);
        put_u64(&mut h, 40, gpt_first_usable_lba(sector));
        put_u64(&mut h, 48, backup_header - gpt_reserved_blocks(sector));
        h[56..72].copy_from_slice(&disk_guid);
        put_u64(&mut h, 72, part_lba);
        put_u32(&mut h, 80, 128);
        put_u32(&mut h, 84, 128);
        put_u32(&mut h, 88, array_crc);
        let crc = embedded_panic_crc32(&h[..92]);
        put_u32(&mut h, 16, crc);
        h
    };

    let primary = write_header(1, backup_header, 2);
    image[SECTOR_BYTES..SECTOR_BYTES * 2].copy_from_slice(&primary);
    let backup_entries = backup_header - 32;
    let backup_at = (backup_entries * u64::from(sector)) as usize;
    image[backup_at..backup_at + array.len()].copy_from_slice(&array);
    let backup = write_header(backup_header, 1, backup_entries);
    let backup_header_at = (backup_header * u64::from(sector)) as usize;
    image[backup_header_at..backup_header_at + SECTOR_BYTES].copy_from_slice(&backup);

    let part_at = (first_lba * u64::from(sector)) as usize;
    image[part_at..part_at + payload.len()].copy_from_slice(payload);
    image
}

pub fn wrap_udif(disk: &[u8]) -> Result<Vec<u8>, String> {
    if !disk.len().is_multiple_of(SECTOR_BYTES) {
        return Err("UDIF data fork must be a whole number of 512-byte sectors".into());
    }
    let sector_count = disk.len() as u64 / SECTOR_BYTES as u64;
    let mish = encode_mish(sector_count, disk.len() as u64);
    let xml = udif_plist(&mish);
    let mut out = Vec::with_capacity(disk.len() + xml.len() + 512);
    out.extend_from_slice(disk);
    let xml_offset = out.len() as u64;
    out.extend_from_slice(xml.as_bytes());
    let xml_length = xml.len() as u64;
    let mut koly = vec![0u8; 512];
    koly[0..4].copy_from_slice(b"koly");
    put_be_u32(&mut koly, 4, 4);
    put_be_u32(&mut koly, 8, 512);
    put_be_u64(&mut koly, 24, 0);
    put_be_u64(&mut koly, 32, disk.len() as u64);
    put_be_u64(&mut koly, 216, xml_offset);
    put_be_u64(&mut koly, 224, xml_length);
    put_be_u32(&mut koly, 488, 2);
    put_be_u64(&mut koly, 492, sector_count);
    out.extend_from_slice(&koly);
    Ok(out)
}

fn encode_mish(sector_count: u64, data_len: u64) -> Vec<u8> {
    let mut b = vec![0u8; 204 + 80];
    b[0..4].copy_from_slice(b"mish");
    put_be_u32(&mut b, 4, 1);
    put_be_u64(&mut b, 8, 0);
    put_be_u64(&mut b, 16, sector_count);
    put_be_u64(&mut b, 24, 0);
    put_be_u32(&mut b, 32, 1);
    put_be_u32(&mut b, 36, 0);
    put_be_u32(&mut b, 200, 2);
    let run = 204;
    put_be_u32(&mut b, run, 0x0000_0001);
    put_be_u64(&mut b, run + 8, 0);
    put_be_u64(&mut b, run + 16, sector_count);
    put_be_u64(&mut b, run + 24, 0);
    put_be_u64(&mut b, run + 32, data_len);
    let term = 244;
    put_be_u32(&mut b, term, 0xFFFF_FFFF);
    b
}

fn udif_plist(mish: &[u8]) -> String {
    let b64 = base64_encode(mish);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>resource-fork</key>
<dict>
<key>blkx</key>
<array>
<dict>
<key>Attributes</key>
<string>0x0050</string>
<key>Data</key>
<data>
{b64}
</data>
<key>ID</key>
<string>0</string>
<key>Name</key>
<string>Apple_APFS</string>
</dict>
</array>
</dict>
</dict>
</plist>
"#
    )
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
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
        const BT_KV_NONALIGNED: u32 = 0x40;
        const BT_SEQUENTIAL_INSERT: u32 = 0x02;
        put_u32(&mut block, info, BT_KV_NONALIGNED | BT_SEQUENTIAL_INSERT);
        put_u32(&mut block, info + 4, block_size as u32);
        put_u32(&mut block, info + 8, 0);
        put_u32(&mut block, info + 12, 0);
        let longest_key = records.iter().map(|(k, _)| k.len()).max().unwrap_or(0) as u32;
        let longest_val = records.iter().map(|(_, v)| v.len()).max().unwrap_or(0) as u32;
        put_u32(&mut block, info + 16, longest_key);
        put_u32(&mut block, info + 20, longest_val);
        put_u64(&mut block, info + 24, records.len() as u64);
        put_u64(&mut block, info + 32, 1);
    }
    block
}

fn omap_record(oid: u64, xid: u64, paddr: u64) -> (Vec<u8>, Vec<u8>) {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&oid.to_le_bytes());
    key.extend_from_slice(&xid.to_le_bytes());
    let mut val = vec![0u8; 16];
    put_u32(&mut val, 4, APFS_BLOCK);
    put_u64(&mut val, 8, paddr);
    (key, val)
}

fn write_nxsb(
    block_count: u64,
    uuid: [u8; 16],
    omap_paddr: u64,
    vol_oids: &[u64],
    xid: u64,
    oid: u64,
) -> Vec<u8> {
    let mut b = vec![0u8; APFS_BLOCK as usize];
    put_u32(&mut b, 0x20, NX_MAGIC);
    put_u32(&mut b, 0x24, APFS_BLOCK);
    put_u64(&mut b, 0x28, block_count);
    b[0x48..0x58].copy_from_slice(&uuid);
    put_u64(&mut b, 0x58, 4096);
    put_u64(&mut b, 0x60, xid + 1);
    put_u32(&mut b, 0x68, 8);
    put_u32(&mut b, 0x6C, 8);
    put_u64(&mut b, 0x70, 1);
    put_u64(&mut b, 0x78, 9);
    put_u32(&mut b, 0x8C, 1);
    put_u64(&mut b, 0xA0, omap_paddr);
    put_u32(&mut b, 0xB4, vol_oids.len() as u32);
    for (i, oid_v) in vol_oids.iter().enumerate() {
        put_u64(&mut b, 0xB8 + i * 8, *oid_v);
    }
    obj_stamp(&mut b, oid, xid, TYPE_NX_SUPERBLOCK | OBJ_EPHEMERAL, 0);
    b
}

fn write_omap(tree_paddr: u64, xid: u64, paddr: u64) -> Vec<u8> {
    let mut b = vec![0u8; APFS_BLOCK as usize];
    put_u32(&mut b, 0x28, TYPE_BTREE | OBJ_PHYSICAL);
    put_u64(&mut b, 0x30, tree_paddr);
    obj_stamp(&mut b, paddr, xid, TYPE_OMAP | OBJ_PHYSICAL, 0);
    b
}

fn write_apsb(
    name: &str,
    role: u16,
    uuid: [u8; 16],
    omap_paddr: u64,
    fs_oid: u64,
    xid: u64,
    oid: u64,
) -> Vec<u8> {
    let mut b = vec![0u8; APFS_BLOCK as usize];
    put_u32(&mut b, 0x20, APFS_MAGIC);
    put_u64(&mut b, 0x80, omap_paddr);
    put_u64(&mut b, 0x88, fs_oid);
    b[0xF0..0x100].copy_from_slice(&uuid);
    put_u64(&mut b, 0x108, APFS_FS_UNENCRYPTED);
    let name_bytes = name.as_bytes();
    b[0x2C0..0x2C0 + name_bytes.len()].copy_from_slice(name_bytes);
    put_u16(&mut b, 0x3C4, role);
    obj_stamp(&mut b, oid, xid, TYPE_FS | OBJ_VIRTUAL, 0);
    b
}

fn inode_key(oid: u64) -> Vec<u8> {
    ((J_INODE << 60) | oid).to_le_bytes().to_vec()
}

fn inode_val(
    parent: u64,
    oid: u64,
    mode: u16,
    nchildren: u32,
    dstream_size: Option<u64>,
) -> Vec<u8> {
    let mut value = vec![0u8; INODE_XFIELDS_OFFSET];
    put_u64(&mut value, 0x00, parent);
    put_u64(&mut value, 0x08, oid);
    put_u32(&mut value, 0x38, nchildren);
    put_u16(&mut value, 0x50, mode);
    if let Some(size) = dstream_size {
        let mut dstream = vec![0u8; DSTREAM_BYTES];
        put_u64(&mut dstream, 0, size);
        put_u64(&mut dstream, 8, u64::from(APFS_BLOCK));
        value.extend_from_slice(&1u16.to_le_bytes());
        value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes());
        value.push(INO_EXT_TYPE_DSTREAM);
        value.push(0);
        value.extend_from_slice(&(DSTREAM_BYTES as u16).to_le_bytes());
        value.extend_from_slice(&dstream);
    }
    value
}

fn drec_key(parent: u64, name: &str) -> Vec<u8> {
    let mut key = ((J_DIR_REC << 60) | parent).to_le_bytes().to_vec();
    let nbytes = (name.len() + 1) as u16;
    key.extend_from_slice(&nbytes.to_le_bytes());
    key.extend_from_slice(name.as_bytes());
    key.push(0);
    key
}

fn drec_val(file_id: u64, dt: u16) -> Vec<u8> {
    let mut val = vec![0u8; 0x12];
    put_u64(&mut val, 0, file_id);
    put_u16(&mut val, 0x10, dt);
    val
}

fn extent_key(oid: u64, logical: u64) -> Vec<u8> {
    let mut key = ((J_FILE_EXTENT << 60) | oid).to_le_bytes().to_vec();
    key.extend_from_slice(&logical.to_le_bytes());
    key
}

fn extent_val(len: u64, phys: u64) -> Vec<u8> {
    let mut val = vec![0u8; 16];
    put_u64(&mut val, 0, len);
    put_u64(&mut val, 8, phys);
    val
}

fn utf16le_name(name: &str) -> [u8; 72] {
    let mut out = [0u8; 72];
    for (i, unit) in name.encode_utf16().take(36).enumerate() {
        let b = unit.to_le_bytes();
        out[i * 2] = b[0];
        out[i * 2 + 1] = b[1];
    }
    out
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

fn put_be_u32(buf: &mut [u8], at: usize, v: u32) {
    buf[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_be_u64(buf: &mut [u8], at: usize, v: u64) {
    buf[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apfs_read::{
        ApfsContainer, DT_DIR, DT_LNK, DT_REG, VolumeChoice, container_geometry_of,
    };
    use crate::apfs_verify::SliceBlocks;

    #[test]
    fn the_fixture_container_holds_a_directory_a_file_and_a_symlink() {
        let image = container_bytes();
        assert_eq!(&image[0x20..0x24], &NX_MAGIC.to_le_bytes());
        let (block_size, block_count) = container_geometry_of(&image).expect("geometry");
        let mut blocks = SliceBlocks::new(&image, block_size);
        let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count).expect("mount");
        let volumes = apfs.volumes().expect("volumes");
        assert_eq!(volumes[0].name, FIXTURE_VOLUME);
        let vol = apfs
            .open_volume_chosen(&VolumeChoice::Named(FIXTURE_VOLUME.to_string()))
            .expect("volume");

        let root = apfs.list_directory(&vol, "/").expect("list /");
        assert!(
            root.iter()
                .any(|e| e.name == FIXTURE_DIR && e.entry_type == DT_DIR),
            "root must list {FIXTURE_DIR}: {root:?}"
        );

        let docs = apfs
            .list_directory(&vol, &format!("/{FIXTURE_DIR}"))
            .expect("list /docs");
        assert!(
            docs.iter()
                .any(|e| e.name == FIXTURE_FILE && e.entry_type == DT_REG),
            "{docs:?}"
        );
        assert!(
            docs.iter()
                .any(|e| e.name == FIXTURE_SYMLINK && e.entry_type == DT_LNK),
            "{docs:?}"
        );
        assert!(
            docs.iter()
                .any(|e| e.name == FIXTURE_NESTED && e.entry_type == DT_DIR),
            "{docs:?}"
        );

        let nested = apfs
            .list_directory(&vol, &format!("/{FIXTURE_DIR}/{FIXTURE_NESTED}"))
            .expect("enter nested");
        assert!(
            nested.iter().any(|e| e.name == FIXTURE_NESTED_FILE),
            "{nested:?}"
        );

        let mut file_bytes = Vec::new();
        apfs.extract(
            &vol,
            &format!("/{FIXTURE_DIR}/{FIXTURE_FILE}"),
            0,
            None,
            &mut file_bytes,
        )
        .expect("extract");
        assert_eq!(file_bytes, FIXTURE_FILE_BYTES);

        let target = apfs
            .read_symlink(&vol, &format!("/{FIXTURE_DIR}/{FIXTURE_SYMLINK}"))
            .expect("symlink");
        assert_eq!(target, FIXTURE_SYMLINK_TARGET);

        let facts = apfs
            .stat(&vol, &format!("/{FIXTURE_DIR}/{FIXTURE_SYMLINK}"))
            .expect("stat link");
        assert!(facts.is_symlink());
    }

    fn symlink_xattr_fixture(streamed: bool, target: &[u8]) -> Vec<u8> {
        let mut image = container_bytes();
        let mut key = ((4u64 << 60) | LINK_INO).to_le_bytes().to_vec();
        let name = b"com.apple.fs.symlink\0";
        key.extend_from_slice(&(name.len() as u16).to_le_bytes());
        key.extend_from_slice(name);
        let stream_id = 30u64;
        let data = if streamed {
            let mut data = vec![0u8; 48];
            put_u64(&mut data, 0, stream_id);
            put_u64(&mut data, 8, target.len() as u64);
            put_u64(&mut data, 16, u64::from(APFS_BLOCK));
            data
        } else {
            target.to_vec()
        };
        let mut value = Vec::new();
        value.extend_from_slice(&(if streamed { 1u16 } else { 2u16 }).to_le_bytes());
        value.extend_from_slice(&(data.len() as u16).to_le_bytes());
        value.extend_from_slice(&data);
        let mut records = vec![
            (
                inode_key(ROOT_INO),
                inode_val(1, ROOT_INO, S_IFDIR | 0o755, 1, None),
            ),
            (drec_key(ROOT_INO, FIXTURE_DIR), drec_val(DOCS_INO, DT_DIR)),
            (
                drec_key(ROOT_INO, FIXTURE_SYMLINK),
                drec_val(LINK_INO, DT_LNK),
            ),
            (
                inode_key(DOCS_INO),
                inode_val(ROOT_INO, DOCS_INO, S_IFDIR | 0o755, 2, None),
            ),
            (
                drec_key(DOCS_INO, FIXTURE_SYMLINK),
                drec_val(LINK_INO, DT_LNK),
            ),
            (drec_key(DOCS_INO, FIXTURE_FILE), drec_val(FILE_INO, DT_REG)),
            (
                inode_key(FILE_INO),
                inode_val(
                    DOCS_INO,
                    FILE_INO,
                    S_IFREG | 0o644,
                    1,
                    Some(FIXTURE_FILE_BYTES.len() as u64),
                ),
            ),
            (
                extent_key(FILE_INO, 0),
                extent_val(u64::from(APFS_BLOCK), FILE_DATA_BLK),
            ),
            (
                inode_key(LINK_INO),
                inode_val(ROOT_INO, LINK_INO, S_IFLNK | 0o777, 1, None),
            ),
            (key, value),
        ];
        if streamed {
            records.push((
                extent_key(stream_id, 0),
                extent_val(u64::from(APFS_BLOCK), LINK_DATA_BLK),
            ));
            let at = (LINK_DATA_BLK * u64::from(APFS_BLOCK)) as usize;
            image[at..at + target.len()].copy_from_slice(target);
        }
        let mut fs = btree_leaf(APFS_BLOCK as usize, &records, true);
        obj_stamp(&mut fs, VOL_FS, XID, TYPE_BTREE | OBJ_PHYSICAL, 0);
        let at = (VOL_FS * u64::from(APFS_BLOCK)) as usize;
        image[at..at + fs.len()].copy_from_slice(&fs);
        image
    }

    fn assert_symlink_xattr_target(streamed: bool) {
        let target = b"/usr/share/firmware/wifi/C-4388__s-B0/canary-X0.txcb\0";
        let image = symlink_xattr_fixture(streamed, target);
        let (block_size, block_count) = container_geometry_of(&image).unwrap();
        let mut blocks = SliceBlocks::new(&image, block_size);
        let mut apfs = ApfsContainer::mount(&mut blocks, block_size, block_count).unwrap();
        let vol = apfs.open_volume_chosen(&VolumeChoice::Index(0)).unwrap();
        let path = format!("/{FIXTURE_SYMLINK}");
        assert_eq!(apfs.stat(&vol, &path).unwrap().stream_size, None);
        assert_eq!(
            apfs.read_symlink(&vol, &path).unwrap(),
            std::str::from_utf8(&target[..target.len() - 1]).unwrap()
        );
    }

    #[test]
    fn symlink_embedded_xattr_without_inode_stream_yields_target() {
        assert_symlink_xattr_target(false);
    }

    #[test]
    fn symlink_streamed_xattr_uses_its_own_stream_object() {
        assert_symlink_xattr_target(true);
    }

    #[test]
    fn symlink_metadata_preserves_dangling_target_without_creating_a_file() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("dangling.img");
        let target = "/docs/missing.txcb";
        std::fs::write(
            &image,
            wrap_gpt(&symlink_xattr_fixture(false, target.as_bytes())),
        )
        .unwrap();
        let paths = vec!["/docs".to_string()];
        let output =
            crate::explorer_image::extract_paths_with_link_metadata(&image, &paths).unwrap();
        let links: std::collections::BTreeMap<String, String> = serde_json::from_slice(
            &std::fs::read(output.path().join(".appleutils-symlinks.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(links.get("/docs/link").map(String::as_str), Some(target));
        assert!(!output.path().join("docs/link").exists());
        assert_eq!(
            std::fs::read(output.path().join("docs/readme.txt")).unwrap(),
            FIXTURE_FILE_BYTES
        );
        assert!(crate::explorer_image::extract_paths_from_unique_volume(&image, &paths).is_err());
    }

    #[test]
    fn symlink_metadata_preserves_relative_target_and_materializes_its_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let image = temp.path().join("linked.img");
        std::fs::write(
            &image,
            wrap_gpt(&symlink_xattr_fixture(false, b"readme.txt")),
        )
        .unwrap();
        let paths = vec!["/docs".to_string()];
        let output =
            crate::explorer_image::extract_paths_with_link_metadata(&image, &paths).unwrap();
        let links: std::collections::BTreeMap<String, String> = serde_json::from_slice(
            &std::fs::read(output.path().join(".appleutils-symlinks.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            links.get("/docs/link").map(String::as_str),
            Some("readme.txt")
        );
        let link = output.path().join("docs/link");
        assert!(
            !std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(link).unwrap(), FIXTURE_FILE_BYTES);
    }

    #[test]
    fn gpt_wrap_does_not_put_nxsb_at_byte_zero() {
        let disk = gpt_disk();
        assert_ne!(&disk[0x20..0x24], &NX_MAGIC.to_le_bytes());
        assert_eq!(&disk[SECTOR_BYTES..SECTOR_BYTES + 8], &GPT_SIGNATURE);
    }
}
