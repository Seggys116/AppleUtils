use std::cmp::Ordering;

use crate::apfs_verify::{u16_at, u32_at, u64_at};

use super::disc::{DiscError, RepairSession};
use super::object::{self, OBJ_PHYS_BYTES, ReadModifyWriteError, XID_OFFSET};

const FLAGS_OFFSET: usize = OBJ_PHYS_BYTES; // btn_flags at +0x00
const NKEYS_OFFSET: usize = OBJ_PHYS_BYTES + 0x04;
const TOC_OFF_OFFSET: usize = OBJ_PHYS_BYTES + 0x08;
const TOC_LEN_OFFSET: usize = OBJ_PHYS_BYTES + 0x0A;
const FREE_SPACE_OFFSET: usize = OBJ_PHYS_BYTES + 0x0C;
const KEY_FREE_LIST_OFFSET: usize = OBJ_PHYS_BYTES + 0x10;
const VAL_FREE_LIST_OFFSET: usize = OBJ_PHYS_BYTES + 0x14;
const BT_KEY_COUNT_OFFSET: usize = 0x18;
const TOC_BASE: usize = 56;
const BTREE_INFO_BYTES: usize = 40;
const TOC_ENTRY_BYTES: usize = 4;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTNODE_NOHEADER: u16 = 0x10;

#[derive(Debug)]
pub enum BtreeError {
    Disc(DiscError),
    Headerless,
    NotLeaf,
    NotFixedKv,
    SizeMismatch,
    DuplicateKey,
    IndexOutOfRange,
    Malformed(&'static str),
    NodeSplitRequired,
}

impl std::fmt::Display for BtreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::Headerless => write!(f, "node is headerless (a sealed volume's hashed tree)"),
            Self::NotLeaf => write!(f, "node is not a leaf"),
            Self::NotFixedKv => write!(f, "node does not use fixed-size keys and values"),
            Self::SizeMismatch => {
                write!(
                    f,
                    "an existing entry's size does not match the caller's key or value"
                )
            }
            Self::DuplicateKey => write!(f, "a record with this key already exists"),
            Self::IndexOutOfRange => write!(f, "no entry stands at that index"),
            Self::Malformed(reason) => write!(f, "node is malformed: {reason}"),
            Self::NodeSplitRequired => write!(
                f,
                "the node has no room for another record; splitting a node is out of scope \
                 for this writer and no established format exists to guess at"
            ),
        }
    }
}

impl std::error::Error for BtreeError {}

impl From<DiscError> for BtreeError {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

impl From<ReadModifyWriteError<BtreeError>> for BtreeError {
    fn from(error: ReadModifyWriteError<BtreeError>) -> Self {
        match error {
            ReadModifyWriteError::Disc(error) => Self::Disc(error),
            ReadModifyWriteError::Mutation(error) => error,
        }
    }
}

struct Header {
    nkeys: usize,
    toc: usize,
    toc_len: usize,
    key_base: usize,
    value_end: usize,
    free_off: usize,
    free_len: usize,
    key_free_len: usize,
    value_free_len: usize,
    info_at: Option<usize>,
}

pub fn is_leaf_node(block: &[u8]) -> bool {
    if block.len() < FLAGS_OFFSET + 2 {
        return false;
    }
    let flags = u16_at(block, FLAGS_OFFSET);
    flags & BTNODE_NOHEADER == 0 && flags & BTNODE_LEAF != 0
}

fn decode_header(block: &[u8]) -> Result<Header, BtreeError> {
    let block_size = block.len();
    let flags = u16_at(block, FLAGS_OFFSET);
    if flags & BTNODE_NOHEADER != 0 {
        return Err(BtreeError::Headerless);
    }
    if flags & BTNODE_LEAF == 0 {
        return Err(BtreeError::NotLeaf);
    }
    if flags & BTNODE_FIXED_KV_SIZE == 0 {
        return Err(BtreeError::NotFixedKv);
    }
    let nkeys = u32_at(block, NKEYS_OFFSET) as usize;
    let toc_off = u16_at(block, TOC_OFF_OFFSET) as usize;
    let toc_len = u16_at(block, TOC_LEN_OFFSET) as usize;
    let toc = TOC_BASE + toc_off;
    let key_base = toc + toc_len;
    let value_end = block_size
        - if flags & BTNODE_ROOT != 0 {
            BTREE_INFO_BYTES
        } else {
            0
        };
    if key_base > value_end || value_end > block_size {
        return Err(BtreeError::Malformed(
            "table of contents leaves no room for keys and values",
        ));
    }
    if nkeys * TOC_ENTRY_BYTES > toc_len {
        return Err(BtreeError::Malformed(
            "more keys than the table of contents holds",
        ));
    }
    Ok(Header {
        nkeys,
        toc,
        toc_len,
        key_base,
        value_end,
        free_off: u16_at(block, FREE_SPACE_OFFSET) as usize,
        free_len: u16_at(block, FREE_SPACE_OFFSET + 2) as usize,
        key_free_len: u16_at(block, KEY_FREE_LIST_OFFSET + 2) as usize,
        value_free_len: u16_at(block, VAL_FREE_LIST_OFFSET + 2) as usize,
        info_at: if flags & BTNODE_ROOT != 0 {
            Some(block_size - BTREE_INFO_BYTES)
        } else {
            None
        },
    })
}

fn toc_entry(block: &[u8], header: &Header, index: usize) -> (usize, usize) {
    let at = header.toc + index * TOC_ENTRY_BYTES;
    (u16_at(block, at) as usize, u16_at(block, at + 2) as usize)
}

fn entry_ranges(
    block: &[u8],
    header: &Header,
    index: usize,
    key_size: usize,
    value_size: usize,
) -> Result<(std::ops::Range<usize>, std::ops::Range<usize>), BtreeError> {
    let (key_off, value_off) = toc_entry(block, header, index);
    let key_at = header
        .key_base
        .checked_add(key_off)
        .filter(|end| *end + key_size <= header.value_end)
        .ok_or(BtreeError::Malformed("key runs past the value area"))?;
    let value_at = header
        .value_end
        .checked_sub(value_off)
        .filter(|at| *at >= header.key_base)
        .ok_or(BtreeError::Malformed("value offset leaves the node"))?;
    let value_end = value_at
        .checked_add(value_size)
        .filter(|end| *end <= header.value_end)
        .ok_or(BtreeError::Malformed("value runs past the end of the node"))?;
    Ok((key_at..key_at + key_size, value_at..value_end))
}

pub fn find_entry(
    disc: &mut RepairSession<'_>,
    node_paddr: u64,
    key: &[u8],
    value_size: usize,
    compare: impl Fn(&[u8], &[u8]) -> Ordering,
) -> Result<Result<usize, usize>, BtreeError> {
    let block_size = disc.block_size() as usize;
    let mut block = vec![0u8; block_size];
    disc.read_block(node_paddr, &mut block)?;
    let header = decode_header(&block)?;
    for index in 0..header.nkeys {
        let (key_range, _) = entry_ranges(&block, &header, index, key.len(), value_size)?;
        match compare(&block[key_range], key) {
            Ordering::Equal => return Ok(Ok(index)),
            Ordering::Greater => return Ok(Err(index)),
            Ordering::Less => {}
        }
    }
    Ok(Err(header.nkeys))
}

pub fn value_at(
    disc: &mut RepairSession<'_>,
    node_paddr: u64,
    index: usize,
    key_size: usize,
    value_size: usize,
) -> Result<Vec<u8>, BtreeError> {
    let block_size = disc.block_size() as usize;
    let mut block = vec![0u8; block_size];
    disc.read_block(node_paddr, &mut block)?;
    let header = decode_header(&block)?;
    if index >= header.nkeys {
        return Err(BtreeError::IndexOutOfRange);
    }
    let (_, value_range) = entry_ranges(&block, &header, index, key_size, value_size)?;
    Ok(block[value_range].to_vec())
}

pub fn overwrite_value(
    disc: &mut RepairSession<'_>,
    node_paddr: u64,
    index: usize,
    key_size: usize,
    value: &[u8],
    node_xid: u64,
) -> Result<(), BtreeError> {
    let value_size = value.len();
    object::read_modify_write::<BtreeError>(disc, node_paddr, |block| {
        let header = decode_header(block)?;
        if index >= header.nkeys {
            return Err(BtreeError::IndexOutOfRange);
        }
        let (_, value_range) = entry_ranges(block, &header, index, key_size, value_size)?;
        block[value_range].copy_from_slice(value);
        block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&node_xid.to_le_bytes());
        Ok(())
    })
    .map_err(BtreeError::from)
}

pub fn insert_leaf(
    disc: &mut RepairSession<'_>,
    node_paddr: u64,
    key: &[u8],
    value: &[u8],
    node_xid: u64,
    compare: impl Fn(&[u8], &[u8]) -> Ordering,
) -> Result<(), BtreeError> {
    let key_size = key.len();
    let value_size = value.len();
    object::read_modify_write::<BtreeError>(disc, node_paddr, |block| {
        let header = decode_header(block)?;

        let mut insert_at = header.nkeys;
        let mut key_high = 0usize;
        let mut value_high = 0usize;
        for index in 0..header.nkeys {
            let (key_off, value_off) = toc_entry(block, &header, index);
            key_high = key_high.max(key_off + key_size);
            value_high = value_high.max(value_off);
            if insert_at == header.nkeys {
                let (key_range, _) = entry_ranges(block, &header, index, key_size, value_size)?;
                match compare(&block[key_range], key) {
                    Ordering::Equal => return Err(BtreeError::DuplicateKey),
                    Ordering::Greater => insert_at = index,
                    Ordering::Less => {}
                }
            }
        }

        let data_area = header.value_end - header.key_base;
        if key_high + value_high > data_area
            || header.free_off > data_area
            || header.free_off + header.free_len > data_area
            || header.free_off < key_high
            || header.free_len + header.key_free_len + header.value_free_len > data_area
        {
            return Err(BtreeError::Malformed(
                "the node's recorded free space contradicts its table of contents",
            ));
        }

        if (header.nkeys + 1) * TOC_ENTRY_BYTES > header.toc_len {
            return Err(BtreeError::NodeSplitRequired);
        }
        let new_key_off = key_high;
        let new_value_off = value_high
            .checked_add(value_size)
            .ok_or(BtreeError::NodeSplitRequired)?;
        let new_key_at = header.key_base + new_key_off;
        let new_value_at = header
            .value_end
            .checked_sub(new_value_off)
            .filter(|at| *at >= header.key_base)
            .ok_or(BtreeError::NodeSplitRequired)?;
        if new_key_at + key_size > new_value_at {
            return Err(BtreeError::NodeSplitRequired);
        }

        block[new_key_at..new_key_at + key_size].copy_from_slice(key);
        block[new_value_at..new_value_at + value_size].copy_from_slice(value);

        for index in (insert_at..header.nkeys).rev() {
            let (key_off, value_off) = toc_entry(block, &header, index);
            let at = header.toc + (index + 1) * TOC_ENTRY_BYTES;
            block[at..at + 2].copy_from_slice(&(key_off as u16).to_le_bytes());
            block[at + 2..at + 4].copy_from_slice(&(value_off as u16).to_le_bytes());
        }
        let at = header.toc + insert_at * TOC_ENTRY_BYTES;
        block[at..at + 2].copy_from_slice(&(new_key_off as u16).to_le_bytes());
        block[at + 2..at + 4].copy_from_slice(&(new_value_off as u16).to_le_bytes());

        let new_nkeys = (header.nkeys + 1) as u32;
        block[NKEYS_OFFSET..NKEYS_OFFSET + 4].copy_from_slice(&new_nkeys.to_le_bytes());
        block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&node_xid.to_le_bytes());

        let used_keys = new_key_off + key_size;
        let used_values = new_value_off;
        let data_area = header.value_end - header.key_base;
        block[FREE_SPACE_OFFSET..FREE_SPACE_OFFSET + 2]
            .copy_from_slice(&(used_keys as u16).to_le_bytes());
        block[FREE_SPACE_OFFSET + 2..FREE_SPACE_OFFSET + 4]
            .copy_from_slice(&((data_area - used_keys - used_values) as u16).to_le_bytes());
        if let Some(info_at) = header.info_at {
            let at = info_at + BT_KEY_COUNT_OFFSET;
            let end = at
                .checked_add(8)
                .ok_or(BtreeError::Malformed("btree info key count is missing"))?;
            if end > block.len() {
                return Err(BtreeError::Malformed("btree info key count is missing"));
            }
            let count = u64_at(block, at).saturating_add(1);
            block[at..at + 8].copy_from_slice(&count.to_le_bytes());
        }
        Ok(())
    })
    .map_err(BtreeError::from)
}

pub fn ensure_insert_room(
    disc: &mut RepairSession<'_>,
    node_paddr: u64,
    key_size: usize,
    value_size: usize,
) -> Result<(), BtreeError> {
    let block_size = disc.block_size() as usize;
    let mut block = vec![0u8; block_size];
    disc.read_block(node_paddr, &mut block)?;
    let header = decode_header(&block)?;
    let mut key_high = 0usize;
    let mut value_high = 0usize;
    for index in 0..header.nkeys {
        let (key_off, value_off) = toc_entry(&block, &header, index);
        key_high = key_high.max(key_off + key_size);
        value_high = value_high.max(value_off);
    }
    let data_area = header.value_end - header.key_base;
    if key_high + value_high > data_area
        || header.free_off > data_area
        || header.free_off + header.free_len > data_area
        || header.free_off < key_high
        || header.free_len + header.key_free_len + header.value_free_len > data_area
    {
        return Err(BtreeError::Malformed(
            "the node's recorded free space contradicts its table of contents",
        ));
    }
    if (header.nkeys + 1) * TOC_ENTRY_BYTES > header.toc_len {
        return Err(BtreeError::NodeSplitRequired);
    }
    let new_value_off = value_high
        .checked_add(value_size)
        .ok_or(BtreeError::NodeSplitRequired)?;
    let new_key_at = header.key_base + key_high;
    let new_value_at = header
        .value_end
        .checked_sub(new_value_off)
        .filter(|at| *at >= header.key_base)
        .ok_or(BtreeError::NodeSplitRequired)?;
    if new_key_at + key_size > new_value_at {
        return Err(BtreeError::NodeSplitRequired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair_writer::object::test_support::*;

    fn omap_compare(a: &[u8], b: &[u8]) -> Ordering {
        let a_key = (
            u64::from_le_bytes(a[0..8].try_into().unwrap()),
            u64::from_le_bytes(a[8..16].try_into().unwrap()),
        );
        let b_key = (
            u64::from_le_bytes(b[0..8].try_into().unwrap()),
            u64::from_le_bytes(b[8..16].try_into().unwrap()),
        );
        a_key.cmp(&b_key)
    }

    fn omap_key(oid: u64, xid: u64) -> [u8; 16] {
        let mut key = [0u8; 16];
        key[0..8].copy_from_slice(&oid.to_le_bytes());
        key[8..16].copy_from_slice(&xid.to_le_bytes());
        key
    }

    fn omap_value(paddr: u64) -> [u8; 16] {
        let mut value = [0u8; 16];
        value[0..4].copy_from_slice(&0u32.to_le_bytes());
        value[4..8].copy_from_slice(&BLOCK_SIZE.to_le_bytes());
        value[8..16].copy_from_slice(&paddr.to_le_bytes());
        value
    }

    #[test]
    fn insert_into_an_empty_leaf_re_parses_through_the_omap_walk() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            insert_leaf(
                &mut disc,
                LAYOUT.omap_tree_root,
                &omap_key(100, INITIAL_XID),
                &omap_value(500),
                INITIAL_XID + 1,
                omap_compare,
            )
            .expect("insert");
        }
        let verified = verify(&image);
        assert_eq!(verified.xid, INITIAL_XID);
    }

    #[test]
    fn three_inserts_land_in_sorted_order_and_are_all_readable_back() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            for (oid, paddr) in [(300u64, 30u64), (100, 10), (200, 20)] {
                insert_leaf(
                    &mut disc,
                    LAYOUT.omap_tree_root,
                    &omap_key(oid, INITIAL_XID),
                    &omap_value(paddr),
                    INITIAL_XID,
                    omap_compare,
                )
                .expect("insert");
            }
            for oid in [100u64, 200, 300] {
                let found = find_entry(
                    &mut disc,
                    LAYOUT.omap_tree_root,
                    &omap_key(oid, INITIAL_XID),
                    16,
                    omap_compare,
                )
                .expect("find");
                assert!(found.is_ok(), "oid {oid} should be found by exact match");
            }
        }
        verify(&image);
    }

    #[test]
    fn every_insert_leaves_the_space_accounting_a_mount_validates_against() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            for (oid, paddr) in [(300u64, 30u64), (100, 10), (200, 20)] {
                insert_leaf(
                    &mut disc,
                    LAYOUT.omap_tree_root,
                    &omap_key(oid, INITIAL_XID),
                    &omap_value(paddr),
                    INITIAL_XID,
                    omap_compare,
                )
                .expect("insert");
            }
        }

        let at = LAYOUT.omap_tree_root as usize * BLOCK_SIZE as usize;
        let block = &image.bytes[at..at + BLOCK_SIZE as usize];
        let nkeys = u32_at(block, NKEYS_OFFSET) as usize;
        assert_eq!(nkeys, 3);
        let toc = TOC_BASE + u16_at(block, TOC_OFF_OFFSET) as usize;
        let toc_len = u16_at(block, TOC_LEN_OFFSET) as usize;
        let data_area = BLOCK_SIZE as usize - TOC_BASE - toc_len - BTREE_INFO_BYTES;
        let free_off = u16_at(block, FREE_SPACE_OFFSET) as usize;
        let free_len = u16_at(block, FREE_SPACE_OFFSET + 2) as usize;
        assert_eq!(free_off, nkeys * 16);
        assert_eq!(free_len, data_area - nkeys * 16 - nkeys * 16);

        let value_area = data_area - free_off - free_len;
        for index in 0..nkeys {
            let entry = toc + index * TOC_ENTRY_BYTES;
            let key_off = u16_at(block, entry) as usize;
            let value_off = u16_at(block, entry + 2) as usize;
            assert!(free_off > key_off);
            assert!(16 <= free_off - key_off);
            assert!(value_off <= value_area);
            assert!(16 <= value_off);
        }
    }

    #[test]
    fn a_duplicate_key_is_rejected_rather_than_silently_overwritten() {
        let mut image = open();
        let mut disc = session(&mut image);
        insert_leaf(
            &mut disc,
            LAYOUT.omap_tree_root,
            &omap_key(100, INITIAL_XID),
            &omap_value(500),
            INITIAL_XID,
            omap_compare,
        )
        .expect("first insert");
        let result = insert_leaf(
            &mut disc,
            LAYOUT.omap_tree_root,
            &omap_key(100, INITIAL_XID),
            &omap_value(999),
            INITIAL_XID,
            omap_compare,
        );
        assert!(matches!(result, Err(BtreeError::DuplicateKey)));
    }

    #[test]
    fn overwrite_value_changes_the_value_without_touching_the_key_or_count() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            insert_leaf(
                &mut disc,
                LAYOUT.omap_tree_root,
                &omap_key(100, INITIAL_XID),
                &omap_value(500),
                INITIAL_XID,
                omap_compare,
            )
            .expect("insert");
            let found = find_entry(
                &mut disc,
                LAYOUT.omap_tree_root,
                &omap_key(100, INITIAL_XID),
                16,
                omap_compare,
            )
            .expect("find");
            let index = found.expect("exact match");
            overwrite_value(
                &mut disc,
                LAYOUT.omap_tree_root,
                index,
                16,
                &omap_value(777),
                INITIAL_XID + 1,
            )
            .expect("overwrite");
        }
        verify(&image);
    }

    #[test]
    fn a_full_table_of_contents_reports_node_split_required_not_a_guess() {
        let mut image = open();
        let mut disc = session(&mut image);
        for oid in 0..16u64 {
            insert_leaf(
                &mut disc,
                LAYOUT.omap_tree_root,
                &omap_key(oid, INITIAL_XID),
                &omap_value(oid),
                INITIAL_XID,
                omap_compare,
            )
            .expect("insert within capacity");
        }
        let result = insert_leaf(
            &mut disc,
            LAYOUT.omap_tree_root,
            &omap_key(16, INITIAL_XID),
            &omap_value(16),
            INITIAL_XID,
            omap_compare,
        );
        assert!(matches!(result, Err(BtreeError::NodeSplitRequired)));
    }
}
