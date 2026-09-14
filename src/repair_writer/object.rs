use crate::apfs_image::{APFS_OBJ_PHYS_BYTES, fletcher64_seal};

use super::disc::{DiscError, RepairSession};

pub const OBJ_PHYS_BYTES: usize = APFS_OBJ_PHYS_BYTES;
pub const OID_OFFSET: usize = 0x08;
pub const XID_OFFSET: usize = 0x10;
pub const TYPE_OFFSET: usize = 0x18;
pub const SUBTYPE_OFFSET: usize = 0x1C;

#[derive(Debug)]
pub enum ObjectWriteError {
    Disc(DiscError),
    BodyTooLarge { block_size: u32, body_len: usize },
}

impl std::fmt::Display for ObjectWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::BodyTooLarge {
                block_size,
                body_len,
            } => write!(
                f,
                "a {body_len}-byte body plus the {OBJ_PHYS_BYTES}-byte object header does not \
                 fit in a {block_size}-byte block"
            ),
        }
    }
}

impl std::error::Error for ObjectWriteError {}

impl From<DiscError> for ObjectWriteError {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

pub fn write_object(
    disc: &mut RepairSession<'_>,
    paddr: u64,
    oid: u64,
    xid: u64,
    o_type: u32,
    subtype: u32,
    body: &[u8],
) -> Result<(), ObjectWriteError> {
    let block_size = disc.block_size();
    if OBJ_PHYS_BYTES + body.len() > block_size as usize {
        return Err(ObjectWriteError::BodyTooLarge {
            block_size,
            body_len: body.len(),
        });
    }
    let mut block = vec![0u8; block_size as usize];
    block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&oid.to_le_bytes());
    block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
    block[TYPE_OFFSET..TYPE_OFFSET + 4].copy_from_slice(&o_type.to_le_bytes());
    block[SUBTYPE_OFFSET..SUBTYPE_OFFSET + 4].copy_from_slice(&subtype.to_le_bytes());
    block[OBJ_PHYS_BYTES..OBJ_PHYS_BYTES + body.len()].copy_from_slice(body);
    fletcher64_seal(&mut block);
    disc.write_block(paddr, &block)?;
    Ok(())
}

#[derive(Debug)]
pub enum ReadModifyWriteError<E> {
    Disc(DiscError),
    Mutation(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ReadModifyWriteError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::Mutation(error) => write!(f, "{error}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for ReadModifyWriteError<E> {}

impl<E> From<DiscError> for ReadModifyWriteError<E> {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

pub fn read_modify_write<E>(
    disc: &mut RepairSession<'_>,
    paddr: u64,
    mutate: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> Result<(), ReadModifyWriteError<E>> {
    let block_size = disc.block_size() as usize;
    let mut block = vec![0u8; block_size];
    disc.read_block(paddr, &mut block)?;
    mutate(&mut block).map_err(ReadModifyWriteError::Mutation)?;
    fletcher64_seal(&mut block);
    disc.write_block(paddr, &block)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::apfs_image::fletcher64_seal;
    use crate::repair_writer::disc::MemoryImage;

    pub(crate) const BLOCK_SIZE: u32 = 4096;
    pub(crate) const BLOCK_COUNT: u64 = 64;

    pub(crate) const OBJ_EPHEMERAL: u32 = 0x8000_0000;
    pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
    pub(crate) const TYPE_NX_SUPERBLOCK: u32 = 0x01;
    pub(crate) const TYPE_BTREE: u32 = 0x02;
    pub(crate) const TYPE_SPACEMAN: u32 = 0x05;
    pub(crate) const TYPE_SPACEMAN_CIB: u32 = 0x07;
    pub(crate) const TYPE_OMAP: u32 = 0x0B;
    pub(crate) const TYPE_CHECKPOINT_MAP: u32 = 0x0C;
    pub(crate) const TYPE_NX_REAPER: u32 = 0x11;

    pub(crate) struct Layout {
        pub(crate) nxsb: u64,
        pub(crate) checkpoint_map: u64,
        pub(crate) reaper: u64,
        pub(crate) spaceman: u64,
        pub(crate) ip_bitmap: u64,
        pub(crate) cib: u64,
        pub(crate) bitmap: u64,
        pub(crate) omap: u64,
        pub(crate) omap_tree_root: u64,
        pub(crate) ip_base: u64,
        pub(crate) ip_block_count: u64,
        pub(crate) free_from: u64,
    }

    pub(crate) const LAYOUT: Layout = Layout {
        nxsb: 0,
        checkpoint_map: 7,
        reaper: 8,
        spaceman: 9,
        ip_bitmap: 16,
        cib: 17,
        bitmap: 18,
        omap: 24,
        omap_tree_root: 25,
        ip_base: 16,
        ip_block_count: 8,
        free_from: 26,
    };

    pub(crate) const INITIAL_XID: u64 = 1;
    pub(crate) const REAPER_OID: u64 = 0x400;
    pub(crate) const SPACEMAN_OID: u64 = 0x401;

    pub(crate) fn allocated_blocks() -> Vec<u64> {
        let mut blocks: Vec<u64> = (0..24).collect();
        blocks.extend([LAYOUT.omap, LAYOUT.omap_tree_root]);
        blocks
    }

    pub(crate) fn build() -> Vec<u8> {
        let mut disk = vec![0u8; BLOCK_SIZE as usize * BLOCK_COUNT as usize];
        let block = |index: u64| -> std::ops::Range<usize> {
            let start = index as usize * BLOCK_SIZE as usize;
            start..start + BLOCK_SIZE as usize
        };

        let mut bitmap = vec![0u8; BLOCK_SIZE as usize];
        for paddr in allocated_blocks() {
            bitmap[(paddr / 8) as usize] |= 1 << (paddr % 8);
        }
        let free_count = BLOCK_COUNT - allocated_blocks().len() as u64;
        disk[block(LAYOUT.bitmap)].copy_from_slice(&bitmap);

        let mut cib_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        cib_body[0x00..0x04].copy_from_slice(&0u32.to_le_bytes());
        cib_body[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());
        let at = 0x08;
        cib_body[at..at + 8].copy_from_slice(&INITIAL_XID.to_le_bytes());
        cib_body[at + 8..at + 16].copy_from_slice(&0u64.to_le_bytes());
        cib_body[at + 16..at + 20].copy_from_slice(&(BLOCK_COUNT as u32).to_le_bytes());
        cib_body[at + 20..at + 24].copy_from_slice(&(free_count as u32).to_le_bytes());
        cib_body[at + 24..at + 32].copy_from_slice(&LAYOUT.bitmap.to_le_bytes());
        write_body(
            &mut disk,
            LAYOUT.cib,
            LAYOUT.cib,
            INITIAL_XID,
            TYPE_SPACEMAN_CIB | OBJ_PHYSICAL,
            0,
            &cib_body,
        );

        let mut sm = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        put_u32(&mut sm, 0x20 - OBJ_PHYS_BYTES, BLOCK_SIZE);
        put_u32(&mut sm, 0x24 - OBJ_PHYS_BYTES, BLOCK_SIZE * 8);
        put_u32(&mut sm, 0x28 - OBJ_PHYS_BYTES, 1);
        put_u32(
            &mut sm,
            0x2C - OBJ_PHYS_BYTES,
            ((BLOCK_SIZE as usize - 0x28) / 8) as u32,
        );
        put_u32(&mut sm, 0x154 - OBJ_PHYS_BYTES, 2520);
        put_u64(&mut sm, 0x30 - OBJ_PHYS_BYTES, BLOCK_COUNT);
        put_u64(&mut sm, 0x38 - OBJ_PHYS_BYTES, 1);
        put_u32(&mut sm, 0x40 - OBJ_PHYS_BYTES, 1);
        put_u32(&mut sm, 0x44 - OBJ_PHYS_BYTES, 0);
        put_u64(&mut sm, 0x48 - OBJ_PHYS_BYTES, free_count);

        const SPACEMAN_STRUCT_SIZE: usize = 2520;
        let xid_offset = SPACEMAN_STRUCT_SIZE;
        let bitmap_offset = align8(xid_offset + 8);
        let next_offset = align8(bitmap_offset + 2);
        let cib_addr_offset = align8(next_offset + 2);
        put_u32(&mut sm, 0x50 - OBJ_PHYS_BYTES, cib_addr_offset as u32);
        put_u64(&mut sm, cib_addr_offset - OBJ_PHYS_BYTES, LAYOUT.cib);
        put_u64(&mut sm, 0x98 - OBJ_PHYS_BYTES, LAYOUT.ip_block_count);
        put_u32(&mut sm, 0xA0 - OBJ_PHYS_BYTES, 1);
        put_u32(&mut sm, 0xA4 - OBJ_PHYS_BYTES, 1);
        put_u64(&mut sm, 0xA8 - OBJ_PHYS_BYTES, LAYOUT.ip_bitmap);
        put_u64(&mut sm, 0xB0 - OBJ_PHYS_BYTES, LAYOUT.ip_base);
        sm[0x140 - OBJ_PHYS_BYTES..0x142 - OBJ_PHYS_BYTES]
            .copy_from_slice(&0xFFFFu16.to_le_bytes());
        sm[0x142 - OBJ_PHYS_BYTES..0x144 - OBJ_PHYS_BYTES]
            .copy_from_slice(&0xFFFFu16.to_le_bytes());
        put_u32(&mut sm, 0x144 - OBJ_PHYS_BYTES, xid_offset as u32);
        put_u32(&mut sm, 0x148 - OBJ_PHYS_BYTES, bitmap_offset as u32);
        put_u32(&mut sm, 0x14C - OBJ_PHYS_BYTES, next_offset as u32);
        put_u64(&mut sm, xid_offset - OBJ_PHYS_BYTES, INITIAL_XID);
        sm[bitmap_offset - OBJ_PHYS_BYTES..bitmap_offset - OBJ_PHYS_BYTES + 2]
            .copy_from_slice(&0u16.to_le_bytes());
        sm[next_offset - OBJ_PHYS_BYTES..next_offset - OBJ_PHYS_BYTES + 2]
            .copy_from_slice(&0xFFFFu16.to_le_bytes());
        write_body(
            &mut disk,
            LAYOUT.spaceman,
            SPACEMAN_OID,
            INITIAL_XID,
            TYPE_SPACEMAN | OBJ_EPHEMERAL,
            0,
            &sm,
        );

        write_body(
            &mut disk,
            LAYOUT.reaper,
            REAPER_OID,
            INITIAL_XID,
            TYPE_NX_REAPER | OBJ_EPHEMERAL,
            0,
            &vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES],
        );

        let mut cpm = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        put_u32(&mut cpm, 0x20 - OBJ_PHYS_BYTES, 1);
        put_u32(&mut cpm, 0x24 - OBJ_PHYS_BYTES, 2);
        write_checkpoint_mapping(
            &mut cpm,
            0,
            TYPE_NX_REAPER | OBJ_EPHEMERAL,
            0,
            REAPER_OID,
            LAYOUT.reaper,
        );
        write_checkpoint_mapping(
            &mut cpm,
            1,
            TYPE_SPACEMAN | OBJ_EPHEMERAL,
            0,
            SPACEMAN_OID,
            LAYOUT.spaceman,
        );
        write_body(
            &mut disk,
            LAYOUT.checkpoint_map,
            LAYOUT.checkpoint_map,
            INITIAL_XID,
            TYPE_CHECKPOINT_MAP | OBJ_PHYSICAL,
            0,
            &cpm,
        );

        let mut omap_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        put_u32(
            &mut omap_body,
            0x28 - OBJ_PHYS_BYTES,
            TYPE_BTREE | OBJ_PHYSICAL,
        );
        put_u64(&mut omap_body, 0x30 - OBJ_PHYS_BYTES, LAYOUT.omap_tree_root);
        write_body(
            &mut disk,
            LAYOUT.omap,
            LAYOUT.omap,
            INITIAL_XID,
            TYPE_OMAP | OBJ_PHYSICAL,
            0,
            &omap_body,
        );

        const BTNODE_ROOT: u16 = 0x1;
        const BTNODE_LEAF: u16 = 0x2;
        const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
        let mut root_body = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        let flags = BTNODE_ROOT | BTNODE_LEAF | BTNODE_FIXED_KV_SIZE;
        root_body[0x20 - OBJ_PHYS_BYTES..0x22 - OBJ_PHYS_BYTES]
            .copy_from_slice(&flags.to_le_bytes());
        root_body[0x22 - OBJ_PHYS_BYTES..0x24 - OBJ_PHYS_BYTES]
            .copy_from_slice(&0u16.to_le_bytes());
        put_u32(&mut root_body, 0x24 - OBJ_PHYS_BYTES, 0);
        root_body[0x28 - OBJ_PHYS_BYTES..0x2A - OBJ_PHYS_BYTES]
            .copy_from_slice(&0u16.to_le_bytes());
        root_body[0x2A - OBJ_PHYS_BYTES..0x2C - OBJ_PHYS_BYTES]
            .copy_from_slice(&64u16.to_le_bytes());
        write_body(
            &mut disk,
            LAYOUT.omap_tree_root,
            LAYOUT.omap_tree_root,
            INITIAL_XID,
            TYPE_BTREE | OBJ_PHYSICAL,
            TYPE_OMAP,
            &root_body,
        );

        let mut sb = vec![0u8; BLOCK_SIZE as usize - OBJ_PHYS_BYTES];
        put_u32(&mut sb, 0x20 - OBJ_PHYS_BYTES, u32::from_le_bytes(*b"NXSB"));
        put_u32(&mut sb, 0x24 - OBJ_PHYS_BYTES, BLOCK_SIZE);
        put_u64(&mut sb, 0x28 - OBJ_PHYS_BYTES, BLOCK_COUNT);
        sb[0x48 - OBJ_PHYS_BYTES..0x58 - OBJ_PHYS_BYTES].copy_from_slice(&[0x11u8; 16]);
        put_u32(&mut sb, 0x68 - OBJ_PHYS_BYTES, 8);
        put_u32(&mut sb, 0x6C - OBJ_PHYS_BYTES, 8);
        put_u64(&mut sb, 0x70 - OBJ_PHYS_BYTES, 0);
        put_u64(&mut sb, 0x78 - OBJ_PHYS_BYTES, 8);
        put_u32(&mut sb, 0x88 - OBJ_PHYS_BYTES, LAYOUT.checkpoint_map as u32);
        put_u32(&mut sb, 0x8C - OBJ_PHYS_BYTES, 2);
        put_u32(&mut sb, 0x90 - OBJ_PHYS_BYTES, 0);
        put_u32(&mut sb, 0x94 - OBJ_PHYS_BYTES, 2);
        put_u32(&mut sb, 0x80 - OBJ_PHYS_BYTES, 1);
        put_u32(&mut sb, 0x84 - OBJ_PHYS_BYTES, 2);
        put_u64(&mut sb, 0x60 - OBJ_PHYS_BYTES, INITIAL_XID + 1);
        put_u64(&mut sb, 0x98 - OBJ_PHYS_BYTES, SPACEMAN_OID);
        put_u64(&mut sb, 0xA0 - OBJ_PHYS_BYTES, LAYOUT.omap);
        put_u64(&mut sb, 0xA8 - OBJ_PHYS_BYTES, REAPER_OID);
        put_u32(&mut sb, 0xB4 - OBJ_PHYS_BYTES, 1);
        put_u64(&mut sb, 0xB8 - OBJ_PHYS_BYTES, 0);
        // version=1, structs_per_fs=4, min_block_count=4
        put_u64(
            &mut sb,
            0x520 - OBJ_PHYS_BYTES,
            1u64 | (4u64 << 16) | (4u64 << 32),
        );
        write_body(
            &mut disk,
            LAYOUT.nxsb,
            1,
            INITIAL_XID,
            TYPE_NX_SUPERBLOCK | OBJ_EPHEMERAL,
            0,
            &sb,
        );

        disk
    }

    const fn align8(v: usize) -> usize {
        (v + 7) & !7
    }

    fn put_u32(body: &mut [u8], at: usize, value: u32) {
        body[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(body: &mut [u8], at: usize, value: u64) {
        body[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_checkpoint_mapping(
        cpm: &mut [u8],
        index: usize,
        o_type: u32,
        subtype: u32,
        oid: u64,
        paddr: u64,
    ) {
        let at = (0x28 - OBJ_PHYS_BYTES) + index * 40;
        put_u32(cpm, at, o_type);
        put_u32(cpm, at + 4, subtype);
        put_u32(cpm, at + 8, BLOCK_SIZE);
        put_u32(cpm, at + 12, 0);
        put_u64(cpm, at + 16, 0);
        put_u64(cpm, at + 24, oid);
        put_u64(cpm, at + 32, paddr);
    }

    fn write_body(
        disk: &mut [u8],
        paddr: u64,
        oid: u64,
        xid: u64,
        o_type: u32,
        subtype: u32,
        body: &[u8],
    ) {
        let start = paddr as usize * BLOCK_SIZE as usize;
        let mut block = vec![0u8; BLOCK_SIZE as usize];
        block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&oid.to_le_bytes());
        block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
        block[TYPE_OFFSET..TYPE_OFFSET + 4].copy_from_slice(&o_type.to_le_bytes());
        block[SUBTYPE_OFFSET..SUBTYPE_OFFSET + 4].copy_from_slice(&subtype.to_le_bytes());
        block[OBJ_PHYS_BYTES..].copy_from_slice(body);
        fletcher64_seal(&mut block);
        disk[start..start + BLOCK_SIZE as usize].copy_from_slice(&block);
    }

    pub(crate) fn open() -> MemoryImage {
        MemoryImage { bytes: build() }
    }

    pub(crate) fn session(image: &mut MemoryImage) -> RepairSession<'_> {
        RepairSession::new(image, 0, BLOCK_SIZE, BLOCK_COUNT)
    }

    pub(crate) fn verify(image: &MemoryImage) -> crate::apfs_verify::VerifiedContainer {
        let mut source = crate::apfs_verify::SliceBlocks::new(&image.bytes, BLOCK_SIZE);
        crate::apfs_verify::verify_container(&mut source).expect("container re-parses cleanly")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[test]
    fn the_fixture_container_verifies_clean_before_any_writer_touches_it() {
        let image = open();
        let verified = verify(&image);
        assert_eq!(verified.xid, INITIAL_XID);
        assert_eq!(
            verified.free_block_count,
            BLOCK_COUNT - allocated_blocks().len() as u64
        );
        assert!(verified.volumes.is_empty());
    }

    #[test]
    fn write_object_stamps_a_verifiable_checksum() {
        let mut image = open();
        let body = {
            let mut disc = session(&mut image);
            let body = vec![0xABu8; disc.block_size() as usize - OBJ_PHYS_BYTES];
            write_object(&mut disc, LAYOUT.free_from, 0x999, 5, 0x0D, 0, &body)
                .expect("write object");
            body
        };

        let start = LAYOUT.free_from as usize * BLOCK_SIZE as usize;
        let block = &image.bytes[start..start + BLOCK_SIZE as usize];
        assert!(crate::apfs_image::fletcher64_valid(block));
        assert_eq!(&block[OID_OFFSET..OID_OFFSET + 8], &0x999u64.to_le_bytes());
        assert_eq!(&block[XID_OFFSET..XID_OFFSET + 8], &5u64.to_le_bytes());
        assert_eq!(
            &block[OBJ_PHYS_BYTES..OBJ_PHYS_BYTES + body.len()],
            body.as_slice()
        );
    }

    #[test]
    fn write_object_rejects_a_body_that_does_not_fit() {
        let mut image = open();
        let mut disc = session(&mut image);
        let body = vec![0u8; disc.block_size() as usize];
        let result = write_object(&mut disc, LAYOUT.free_from, 1, 1, 1, 0, &body);
        assert!(matches!(result, Err(ObjectWriteError::BodyTooLarge { .. })));
    }

    #[test]
    fn read_modify_write_round_trips_a_mutation_and_reseals() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            read_modify_write::<std::convert::Infallible>(&mut disc, LAYOUT.reaper, |block| {
                block[OBJ_PHYS_BYTES] = 0x42;
                Ok(())
            })
            .expect("read-modify-write");
        }

        let start = LAYOUT.reaper as usize * BLOCK_SIZE as usize;
        let block = &image.bytes[start..start + BLOCK_SIZE as usize];
        assert!(crate::apfs_image::fletcher64_valid(block));
        assert_eq!(block[OBJ_PHYS_BYTES], 0x42);
        verify(&image);
    }

    #[test]
    fn read_modify_write_writes_nothing_when_the_mutation_fails() {
        let mut image = open();
        let before = image.bytes.clone();
        {
            let mut disc = session(&mut image);
            let result: Result<(), ReadModifyWriteError<&'static str>> =
                read_modify_write(&mut disc, LAYOUT.reaper, |_block| Err("declined"));
            assert!(matches!(
                result,
                Err(ReadModifyWriteError::Mutation("declined"))
            ));
        }
        assert_eq!(before, image.bytes);
    }
}
