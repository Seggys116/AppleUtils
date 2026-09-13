use std::cmp::Ordering;

use super::btree::{self, BtreeError};
use super::disc::RepairSession;

pub const KEY_BYTES: usize = 16;
pub const VALUE_BYTES: usize = 16;

#[derive(Debug)]
pub struct OmapError(BtreeError);

impl std::fmt::Display for OmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for OmapError {}

impl From<BtreeError> for OmapError {
    fn from(error: BtreeError) -> Self {
        Self(error)
    }
}

fn key_bytes(oid: u64, xid: u64) -> [u8; KEY_BYTES] {
    let mut key = [0u8; KEY_BYTES];
    key[0..8].copy_from_slice(&oid.to_le_bytes());
    key[8..16].copy_from_slice(&xid.to_le_bytes());
    key
}

fn value_bytes(paddr: u64, block_size: u32) -> [u8; VALUE_BYTES] {
    let mut value = [0u8; VALUE_BYTES];
    value[0..4].copy_from_slice(&0u32.to_le_bytes());
    value[4..8].copy_from_slice(&block_size.to_le_bytes());
    value[8..16].copy_from_slice(&paddr.to_le_bytes());
    value
}

fn compare_keys(a: &[u8], b: &[u8]) -> Ordering {
    let a_oid = u64::from_le_bytes(a[0..8].try_into().expect("16-byte omap key"));
    let a_xid = u64::from_le_bytes(a[8..16].try_into().expect("16-byte omap key"));
    let b_oid = u64::from_le_bytes(b[0..8].try_into().expect("16-byte omap key"));
    let b_xid = u64::from_le_bytes(b[8..16].try_into().expect("16-byte omap key"));
    (a_oid, a_xid).cmp(&(b_oid, b_xid))
}

pub fn ensure_upsertable(
    disc: &mut RepairSession<'_>,
    tree_root_paddr: u64,
    oid: u64,
    xid: u64,
) -> Result<(), OmapError> {
    let key = key_bytes(oid, xid);
    match btree::find_entry(disc, tree_root_paddr, &key, VALUE_BYTES, compare_keys) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(_)) => Ok(btree::ensure_insert_room(
            disc,
            tree_root_paddr,
            KEY_BYTES,
            VALUE_BYTES,
        )?),
        Err(error) => Err(error.into()),
    }
}

pub fn upsert(
    disc: &mut RepairSession<'_>,
    tree_root_paddr: u64,
    oid: u64,
    xid: u64,
    paddr: u64,
    node_xid: u64,
) -> Result<(), OmapError> {
    let key = key_bytes(oid, xid);
    let value = value_bytes(paddr, disc.block_size());
    match btree::find_entry(disc, tree_root_paddr, &key, VALUE_BYTES, compare_keys)? {
        Ok(index) => {
            btree::overwrite_value(disc, tree_root_paddr, index, KEY_BYTES, &value, node_xid)?;
        }
        Err(_) => {
            btree::insert_leaf(disc, tree_root_paddr, &key, &value, node_xid, compare_keys)?;
        }
    }
    Ok(())
}

pub fn lookup(
    disc: &mut RepairSession<'_>,
    tree_root_paddr: u64,
    oid: u64,
    xid: u64,
) -> Result<Option<u64>, OmapError> {
    let key = key_bytes(oid, xid);
    let index = match btree::find_entry(disc, tree_root_paddr, &key, VALUE_BYTES, compare_keys)? {
        Ok(index) => index,
        Err(_) => return Ok(None),
    };
    let value = btree::value_at(disc, tree_root_paddr, index, KEY_BYTES, VALUE_BYTES)?;
    Ok(Some(u64::from_le_bytes(
        value[8..16].try_into().expect("16-byte omap value"),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair_writer::object::test_support::*;

    #[test]
    fn upsert_inserts_a_new_entry_that_re_parses_and_is_findable() {
        let mut image = open();
        let found = {
            let mut disc = session(&mut image);
            upsert(
                &mut disc,
                LAYOUT.omap_tree_root,
                0x1234,
                INITIAL_XID,
                200,
                INITIAL_XID,
            )
            .expect("upsert");
            lookup(&mut disc, LAYOUT.omap_tree_root, 0x1234, INITIAL_XID).expect("lookup")
        };
        verify(&image);
        assert_eq!(found, Some(200));
    }

    #[test]
    fn upsert_on_an_existing_key_overwrites_rather_than_duplicates() {
        let mut image = open();
        let found = {
            let mut disc = session(&mut image);
            upsert(
                &mut disc,
                LAYOUT.omap_tree_root,
                0x1234,
                INITIAL_XID,
                200,
                INITIAL_XID,
            )
            .expect("first upsert");
            upsert(
                &mut disc,
                LAYOUT.omap_tree_root,
                0x1234,
                INITIAL_XID,
                999,
                INITIAL_XID + 1,
            )
            .expect("second upsert");
            lookup(&mut disc, LAYOUT.omap_tree_root, 0x1234, INITIAL_XID).expect("lookup")
        };
        verify(&image);
        assert_eq!(found, Some(999));
    }

    #[test]
    fn upsert_on_a_non_leaf_root_is_refused() {
        let mut image = open();
        let mut disc = session(&mut image);
        crate::repair_writer::object::read_modify_write::<std::convert::Infallible>(
            &mut disc,
            LAYOUT.omap_tree_root,
            |block| {
                let flags = u16::from_le_bytes(block[0x20..0x22].try_into().expect("flags"));
                let cleared = flags & !0x2;
                block[0x20..0x22].copy_from_slice(&cleared.to_le_bytes());
                Ok(())
            },
        )
        .expect("clear leaf flag");
        let result = upsert(
            &mut disc,
            LAYOUT.omap_tree_root,
            0x1234,
            INITIAL_XID,
            200,
            INITIAL_XID,
        );
        assert!(
            matches!(result, Err(ref error) if error.to_string().contains("not a leaf")),
            "got {result:?}"
        );
        let preflight = ensure_upsertable(&mut disc, LAYOUT.omap_tree_root, 0x1234, INITIAL_XID);
        assert!(
            matches!(preflight, Err(ref error) if error.to_string().contains("not a leaf")),
            "got {preflight:?}"
        );
    }

    #[test]
    fn lookup_of_an_absent_entry_is_none_not_an_error() {
        let mut image = open();
        let mut disc = session(&mut image);
        let found = lookup(&mut disc, LAYOUT.omap_tree_root, 0xDEAD, 1).expect("lookup");
        assert_eq!(found, None);
    }

    #[test]
    fn two_different_xids_of_the_same_oid_are_distinct_entries() {
        let mut image = open();
        let (xid1, xid2) = {
            let mut disc = session(&mut image);
            upsert(
                &mut disc,
                LAYOUT.omap_tree_root,
                0x1234,
                1,
                200,
                INITIAL_XID,
            )
            .expect("upsert xid 1");
            upsert(
                &mut disc,
                LAYOUT.omap_tree_root,
                0x1234,
                2,
                300,
                INITIAL_XID,
            )
            .expect("upsert xid 2");
            (
                lookup(&mut disc, LAYOUT.omap_tree_root, 0x1234, 1).expect("lookup xid 1"),
                lookup(&mut disc, LAYOUT.omap_tree_root, 0x1234, 2).expect("lookup xid 2"),
            )
        };
        verify(&image);
        assert_eq!(xid1, Some(200));
        assert_eq!(xid2, Some(300));
    }
}
