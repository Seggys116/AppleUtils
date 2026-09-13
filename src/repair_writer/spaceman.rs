use crate::apfs_image::fletcher64_seal;
use crate::apfs_verify::{u32_at, u64_at};

use super::disc::{DiscError, RepairSession};
use super::object::{self, OID_OFFSET, ReadModifyWriteError, XID_OFFSET};

const SM_BLOCK_SIZE_OFFSET: usize = 0x20;
const SM_CIB_COUNT_OFFSET: usize = 0x40;
const SM_FREE_COUNT_OFFSET: usize = 0x48;
const SM_INDIRECT_CIB_OFFSET: usize = 0x44;
const SM_CIB_ADDR_OFFSET_OFFSET: usize = 0x50;

const CHUNK_INFO_BYTES: usize = 32;
const CIB_CHUNK_COUNT_OFFSET: usize = 0x24;
const CIB_ARRAY_OFFSET: usize = 0x28;

#[derive(Debug)]
pub enum SpacemanError {
    Disc(DiscError),
    IndirectChunkAddressing,
    Malformed(&'static str),
    OutOfSpace,
    NotAllocated { paddr: u64 },
    NoSuchChunk { paddr: u64 },
}

impl std::fmt::Display for SpacemanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disc(error) => write!(f, "disc error: {error}"),
            Self::IndirectChunkAddressing => write!(
                f,
                "space manager addresses chunk-info blocks indirectly, a layout this writer \
                 does not establish"
            ),
            Self::Malformed(reason) => write!(f, "space manager is malformed: {reason}"),
            Self::OutOfSpace => write!(
                f,
                "no allocatable block found (every reachable chunk is full, or has no bitmap \
                 block to bootstrap, which is out of scope for this writer)"
            ),
            Self::NotAllocated { paddr } => {
                write!(f, "block {paddr} is not marked allocated, cannot be freed")
            }
            Self::NoSuchChunk { paddr } => {
                write!(
                    f,
                    "block {paddr} does not fall inside any chunk this space manager describes"
                )
            }
        }
    }
}

impl std::error::Error for SpacemanError {}

impl From<DiscError> for SpacemanError {
    fn from(error: DiscError) -> Self {
        Self::Disc(error)
    }
}

impl From<ReadModifyWriteError<SpacemanError>> for SpacemanError {
    fn from(error: ReadModifyWriteError<SpacemanError>) -> Self {
        match error {
            ReadModifyWriteError::Disc(error) => Self::Disc(error),
            ReadModifyWriteError::Mutation(error) => error,
        }
    }
}

fn cib_addrs_from_block(sm: &[u8]) -> Result<Vec<u64>, SpacemanError> {
    if u32_at(sm, SM_INDIRECT_CIB_OFFSET) != 0 {
        return Err(SpacemanError::IndirectChunkAddressing);
    }
    let cib_count = u32_at(sm, SM_CIB_COUNT_OFFSET) as usize;
    let cib_addr_offset = u32_at(sm, SM_CIB_ADDR_OFFSET_OFFSET) as usize;
    if cib_addr_offset + cib_count * 8 > sm.len() {
        return Err(SpacemanError::Malformed(
            "chunk info address array does not fit in the space manager block",
        ));
    }
    Ok((0..cib_count)
        .map(|index| u64_at(sm, cib_addr_offset + index * 8))
        .collect())
}

fn read_cib_addrs(
    disc: &mut RepairSession<'_>,
    spaceman_paddr: u64,
) -> Result<Vec<u64>, SpacemanError> {
    let mut sm = vec![0u8; disc.block_size() as usize];
    disc.read_block(spaceman_paddr, &mut sm)?;
    cib_addrs_from_block(&sm)
}

struct BitmapCopy {
    original_paddr: u64,
    cow_paddr: Option<u64>,
    block: Vec<u8>,
    dirty: bool,
}

struct CibCopy {
    original_paddr: u64,
    cow_paddr: Option<u64>,
    block: Vec<u8>,
    dirty: bool,
    bitmaps: Vec<BitmapCopy>,
}

pub struct PrivateSpaceman {
    spaceman: Vec<u8>,
    cibs: Vec<CibCopy>,
}

impl PrivateSpaceman {
    pub fn load(disc: &mut RepairSession<'_>, spaceman_paddr: u64) -> Result<Self, SpacemanError> {
        let block_size = disc.block_size() as usize;
        let mut spaceman = vec![0u8; block_size];
        disc.read_block(spaceman_paddr, &mut spaceman)?;
        let cib_addrs = cib_addrs_from_block(&spaceman)?;
        let mut cibs = Vec::with_capacity(cib_addrs.len());
        for cib_paddr in cib_addrs {
            let mut cib = vec![0u8; block_size];
            disc.read_block(cib_paddr, &mut cib)?;
            let chunks = u32_at(&cib, CIB_CHUNK_COUNT_OFFSET) as usize;
            let mut bitmaps = Vec::with_capacity(chunks);
            for slot in 0..chunks {
                let record_at = CIB_ARRAY_OFFSET + slot * CHUNK_INFO_BYTES;
                if record_at + CHUNK_INFO_BYTES > cib.len() {
                    return Err(SpacemanError::Malformed(
                        "chunk info block claims more chunks than it holds",
                    ));
                }
                let bitmap_addr = u64_at(&cib, record_at + 24);
                if bitmap_addr == 0 {
                    continue;
                }
                let mut bitmap = vec![0u8; block_size];
                disc.read_block(bitmap_addr, &mut bitmap)?;
                bitmaps.push(BitmapCopy {
                    original_paddr: bitmap_addr,
                    cow_paddr: None,
                    block: bitmap,
                    dirty: false,
                });
            }
            cibs.push(CibCopy {
                original_paddr: cib_paddr,
                cow_paddr: None,
                block: cib,
                dirty: false,
                bitmaps,
            });
        }
        Ok(Self { spaceman, cibs })
    }

    pub fn allocate(&mut self, xid: u64) -> Result<u64, SpacemanError> {
        for cib in &mut self.cibs {
            let chunks = u32_at(&cib.block, CIB_CHUNK_COUNT_OFFSET) as usize;
            for slot in 0..chunks {
                let record_at = CIB_ARRAY_OFFSET + slot * CHUNK_INFO_BYTES;
                if record_at + CHUNK_INFO_BYTES > cib.block.len() {
                    return Err(SpacemanError::Malformed(
                        "chunk info block claims more chunks than it holds",
                    ));
                }
                let chunk_addr = u64_at(&cib.block, record_at + 8);
                let chunk_blocks = u32_at(&cib.block, record_at + 16);
                let bitmap_addr = u64_at(&cib.block, record_at + 24);
                if bitmap_addr == 0 {
                    continue;
                }
                let Some(bitmap) = cib
                    .bitmaps
                    .iter_mut()
                    .find(|bitmap| bitmap.original_paddr == bitmap_addr)
                else {
                    continue;
                };
                let Some(bit) = (0..chunk_blocks as usize)
                    .find(|bit| bitmap.block[bit >> 3] >> (bit & 7) & 1 == 0)
                else {
                    continue;
                };
                bitmap.block[bit >> 3] |= 1 << (bit & 7);
                bitmap.dirty = true;
                let recorded_free = u32_at(&cib.block, record_at + 20);
                let new_free = recorded_free
                    .checked_sub(1)
                    .ok_or(SpacemanError::Malformed(
                        "chunk free count is already zero but a clear bit was found",
                    ))?;
                cib.block[record_at..record_at + 8].copy_from_slice(&xid.to_le_bytes());
                cib.block[record_at + 20..record_at + 24].copy_from_slice(&new_free.to_le_bytes());
                cib.dirty = true;
                decrement_free_count_in(&mut self.spaceman)?;
                return Ok(chunk_addr + bit as u64);
            }
        }
        Err(SpacemanError::OutOfSpace)
    }

    pub fn materialize(
        &mut self,
        disc: &mut RepairSession<'_>,
        xid: u64,
    ) -> Result<Vec<u8>, SpacemanError> {
        loop {
            let mut assigned = false;
            for cib_index in 0..self.cibs.len() {
                if self.cibs[cib_index].dirty && self.cibs[cib_index].cow_paddr.is_none() {
                    let paddr = self.allocate(xid)?;
                    self.cibs[cib_index].cow_paddr = Some(paddr);
                    assigned = true;
                }
                for bitmap_index in 0..self.cibs[cib_index].bitmaps.len() {
                    if self.cibs[cib_index].bitmaps[bitmap_index].dirty
                        && self.cibs[cib_index].bitmaps[bitmap_index]
                            .cow_paddr
                            .is_none()
                    {
                        let paddr = self.allocate(xid)?;
                        self.cibs[cib_index].bitmaps[bitmap_index].cow_paddr = Some(paddr);
                        assigned = true;
                    }
                }
            }
            if !assigned {
                break;
            }
        }

        let cib_count = u32_at(&self.spaceman, SM_CIB_COUNT_OFFSET) as usize;
        let cib_addr_offset = u32_at(&self.spaceman, SM_CIB_ADDR_OFFSET_OFFSET) as usize;
        for (index, cib) in self.cibs.iter_mut().enumerate() {
            for slot in 0..u32_at(&cib.block, CIB_CHUNK_COUNT_OFFSET) as usize {
                let record_at = CIB_ARRAY_OFFSET + slot * CHUNK_INFO_BYTES;
                let bitmap_addr = u64_at(&cib.block, record_at + 24);
                if let Some(bitmap) = cib.bitmaps.iter().find(|bitmap| {
                    bitmap.original_paddr == bitmap_addr || bitmap.current_paddr() == bitmap_addr
                }) && let Some(cow) = bitmap.cow_paddr
                {
                    cib.block[record_at + 24..record_at + 32].copy_from_slice(&cow.to_le_bytes());
                    cib.dirty = true;
                }
            }
            let cib_paddr = cib.cow_paddr.unwrap_or(cib.original_paddr);
            if index < cib_count {
                let at = cib_addr_offset + index * 8;
                self.spaceman[at..at + 8].copy_from_slice(&cib_paddr.to_le_bytes());
            }
            for bitmap in &cib.bitmaps {
                if let Some(cow) = bitmap.cow_paddr {
                    disc.write_block(cow, &bitmap.block)?;
                }
            }
            if let Some(cow) = cib.cow_paddr {
                let mut block = cib.block.clone();
                block[OID_OFFSET..OID_OFFSET + 8].copy_from_slice(&cow.to_le_bytes());
                block[XID_OFFSET..XID_OFFSET + 8].copy_from_slice(&xid.to_le_bytes());
                fletcher64_seal(&mut block);
                disc.write_block(cow, &block)?;
            }
        }
        Ok(self.spaceman.clone())
    }
}

impl BitmapCopy {
    fn current_paddr(&self) -> u64 {
        self.cow_paddr.unwrap_or(self.original_paddr)
    }
}

/// Allocate one free block. Does not restamp the space manager's `o_xid`;
/// that is an ephemeral object whose xid must match the publishing checkpoint.
pub fn allocate(
    disc: &mut RepairSession<'_>,
    spaceman_paddr: u64,
    xid: u64,
) -> Result<u64, SpacemanError> {
    let block_size = disc.block_size() as usize;
    let cib_addrs = read_cib_addrs(disc, spaceman_paddr)?;
    for cib_paddr in cib_addrs {
        let mut cib = vec![0u8; block_size];
        disc.read_block(cib_paddr, &mut cib)?;
        let chunks = u32_at(&cib, CIB_CHUNK_COUNT_OFFSET) as usize;
        for slot in 0..chunks {
            let record_at = CIB_ARRAY_OFFSET + slot * CHUNK_INFO_BYTES;
            if record_at + CHUNK_INFO_BYTES > cib.len() {
                return Err(SpacemanError::Malformed(
                    "chunk info block claims more chunks than it holds",
                ));
            }
            let chunk_addr = u64_at(&cib, record_at + 8);
            let chunk_blocks = u32_at(&cib, record_at + 16);
            let bitmap_addr = u64_at(&cib, record_at + 24);
            if bitmap_addr == 0 {
                continue;
            }
            let mut bitmap = vec![0u8; block_size];
            disc.read_block(bitmap_addr, &mut bitmap)?;
            let Some(bit) =
                (0..chunk_blocks as usize).find(|bit| bitmap[bit >> 3] >> (bit & 7) & 1 == 0)
            else {
                continue;
            };
            bitmap[bit >> 3] |= 1 << (bit & 7);
            disc.write_block(bitmap_addr, &bitmap)?;

            let recorded_free = u32_at(&cib, record_at + 20);
            let new_free = recorded_free
                .checked_sub(1)
                .ok_or(SpacemanError::Malformed(
                    "chunk free count is already zero but a clear bit was found",
                ))?;
            object::read_modify_write::<SpacemanError>(disc, cib_paddr, |block| {
                block[record_at..record_at + 8].copy_from_slice(&xid.to_le_bytes());
                block[record_at + 20..record_at + 24].copy_from_slice(&new_free.to_le_bytes());
                Ok(())
            })?;

            decrement_free_count(disc, spaceman_paddr)?;
            return Ok(chunk_addr + bit as u64);
        }
    }
    Err(SpacemanError::OutOfSpace)
}

pub fn free(
    disc: &mut RepairSession<'_>,
    spaceman_paddr: u64,
    xid: u64,
    paddr: u64,
) -> Result<(), SpacemanError> {
    let block_size = disc.block_size() as usize;
    let cib_addrs = read_cib_addrs(disc, spaceman_paddr)?;
    for cib_paddr in cib_addrs {
        let mut cib = vec![0u8; block_size];
        disc.read_block(cib_paddr, &mut cib)?;
        let chunks = u32_at(&cib, CIB_CHUNK_COUNT_OFFSET) as usize;
        for slot in 0..chunks {
            let record_at = CIB_ARRAY_OFFSET + slot * CHUNK_INFO_BYTES;
            if record_at + CHUNK_INFO_BYTES > cib.len() {
                return Err(SpacemanError::Malformed(
                    "chunk info block claims more chunks than it holds",
                ));
            }
            let chunk_addr = u64_at(&cib, record_at + 8);
            let chunk_blocks = u32_at(&cib, record_at + 16) as u64;
            if paddr < chunk_addr || paddr >= chunk_addr + chunk_blocks {
                continue;
            }
            let bitmap_addr = u64_at(&cib, record_at + 24);
            if bitmap_addr == 0 {
                return Err(SpacemanError::NotAllocated { paddr });
            }
            let bit = (paddr - chunk_addr) as usize;
            let mut bitmap = vec![0u8; block_size];
            disc.read_block(bitmap_addr, &mut bitmap)?;
            if bitmap[bit >> 3] >> (bit & 7) & 1 == 0 {
                return Err(SpacemanError::NotAllocated { paddr });
            }
            bitmap[bit >> 3] &= !(1 << (bit & 7));
            disc.write_block(bitmap_addr, &bitmap)?;

            let recorded_free = u32_at(&cib, record_at + 20);
            let new_free = recorded_free + 1;
            object::read_modify_write::<SpacemanError>(disc, cib_paddr, |block| {
                block[record_at..record_at + 8].copy_from_slice(&xid.to_le_bytes());
                block[record_at + 20..record_at + 24].copy_from_slice(&new_free.to_le_bytes());
                Ok(())
            })?;

            increment_free_count(disc, spaceman_paddr)?;
            return Ok(());
        }
    }
    Err(SpacemanError::NoSuchChunk { paddr })
}

fn decrement_free_count_in(spaceman: &mut [u8]) -> Result<(), SpacemanError> {
    let current = u64_at(spaceman, SM_FREE_COUNT_OFFSET);
    let updated = current.checked_sub(1).ok_or(SpacemanError::Malformed(
        "space manager free count is already zero",
    ))?;
    spaceman[SM_FREE_COUNT_OFFSET..SM_FREE_COUNT_OFFSET + 8]
        .copy_from_slice(&updated.to_le_bytes());
    Ok(())
}

fn decrement_free_count(
    disc: &mut RepairSession<'_>,
    spaceman_paddr: u64,
) -> Result<(), SpacemanError> {
    object::read_modify_write::<SpacemanError>(disc, spaceman_paddr, |block| {
        decrement_free_count_in(block)
    })
    .map_err(SpacemanError::from)
}

fn increment_free_count(
    disc: &mut RepairSession<'_>,
    spaceman_paddr: u64,
) -> Result<(), SpacemanError> {
    object::read_modify_write::<SpacemanError>(disc, spaceman_paddr, |block| {
        let current = u64_at(block, SM_FREE_COUNT_OFFSET);
        let updated = current + 1;
        block[SM_FREE_COUNT_OFFSET..SM_FREE_COUNT_OFFSET + 8]
            .copy_from_slice(&updated.to_le_bytes());
        Ok(())
    })
    .map_err(SpacemanError::from)
}

pub fn block_size(disc: &mut RepairSession<'_>, spaceman_paddr: u64) -> Result<u32, SpacemanError> {
    let mut sm = vec![0u8; disc.block_size() as usize];
    disc.read_block(spaceman_paddr, &mut sm)?;
    Ok(u32_at(&sm, SM_BLOCK_SIZE_OFFSET))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repair_writer::object::test_support::*;

    #[test]
    fn private_allocate_does_not_touch_the_published_spaceman_until_materialize() {
        let mut image = open();
        let before = image.bytes.clone();
        let (paddr, original_bitmap, original_cib, original_sm) = {
            let mut disc = session(&mut image);
            let mut private = PrivateSpaceman::load(&mut disc, LAYOUT.spaceman).expect("load");
            let paddr = private.allocate(INITIAL_XID + 1).expect("allocate");
            drop(disc);
            let bitmap_at = LAYOUT.bitmap as usize * BLOCK_SIZE as usize;
            let cib_at = LAYOUT.cib as usize * BLOCK_SIZE as usize;
            let sm_at = LAYOUT.spaceman as usize * BLOCK_SIZE as usize;
            (
                paddr,
                image.bytes[bitmap_at..bitmap_at + BLOCK_SIZE as usize].to_vec(),
                image.bytes[cib_at..cib_at + BLOCK_SIZE as usize].to_vec(),
                image.bytes[sm_at..sm_at + BLOCK_SIZE as usize].to_vec(),
            )
        };
        assert_eq!(before, image.bytes);
        let materialized = {
            let mut disc = session(&mut image);
            let mut private = PrivateSpaceman::load(&mut disc, LAYOUT.spaceman).expect("load");
            let again = private.allocate(INITIAL_XID + 1).expect("allocate");
            assert_eq!(again, paddr);
            private
                .materialize(&mut disc, INITIAL_XID + 1)
                .expect("materialize")
        };
        let bitmap_at = LAYOUT.bitmap as usize * BLOCK_SIZE as usize;
        let cib_at = LAYOUT.cib as usize * BLOCK_SIZE as usize;
        let sm_at = LAYOUT.spaceman as usize * BLOCK_SIZE as usize;
        assert_eq!(
            &image.bytes[bitmap_at..bitmap_at + BLOCK_SIZE as usize],
            original_bitmap.as_slice()
        );
        assert_eq!(
            &image.bytes[cib_at..cib_at + BLOCK_SIZE as usize],
            original_cib.as_slice()
        );
        assert_eq!(
            &image.bytes[sm_at..sm_at + BLOCK_SIZE as usize],
            original_sm.as_slice()
        );
        assert_ne!(materialized, original_sm);
    }

    #[test]
    fn allocate_sets_a_bit_and_the_container_still_verifies_clean() {
        let mut image = open();
        let before = verify(&image);
        let paddr = {
            let mut disc = session(&mut image);
            allocate(&mut disc, LAYOUT.spaceman, INITIAL_XID + 1).expect("allocate")
        };
        assert!(!before.blocks_in_use.contains(&paddr));

        let after = verify(&image);
        assert_eq!(after.free_block_count, before.free_block_count - 1);
    }

    #[test]
    fn allocate_never_returns_the_same_block_twice_and_eventually_reports_out_of_space() {
        let mut image = open();
        let capacity = verify(&image).free_block_count;
        let mut allocated = std::collections::HashSet::new();
        {
            let mut disc = session(&mut image);
            for _ in 0..capacity {
                let paddr = allocate(&mut disc, LAYOUT.spaceman, INITIAL_XID).expect("allocate");
                assert!(allocated.insert(paddr), "allocate returned {paddr} twice");
            }
            let result = allocate(&mut disc, LAYOUT.spaceman, INITIAL_XID);
            assert!(matches!(result, Err(SpacemanError::OutOfSpace)));
        }
        let after = verify(&image);
        assert_eq!(after.free_block_count, 0);
    }

    #[test]
    fn allocating_never_restamps_the_published_space_manager() {
        let mut image = open();
        {
            let mut disc = session(&mut image);
            allocate(&mut disc, LAYOUT.spaceman, INITIAL_XID + 1).expect("allocate");
        }
        let at = LAYOUT.spaceman as usize * BLOCK_SIZE as usize;
        assert_eq!(
            u64_at(
                &image.bytes[at..at + BLOCK_SIZE as usize],
                object::XID_OFFSET
            ),
            INITIAL_XID
        );
        crate::repair_writer::checkpoint::kernel_checks::load_checkpoint_data(
            &image.bytes,
            BLOCK_SIZE as usize,
            LAYOUT.nxsb,
        )
        .expect("the published checkpoint must still load after an allocation");
    }

    #[test]
    fn free_clears_the_bit_and_restores_the_free_count() {
        let mut image = open();
        let before = verify(&image);
        {
            let mut disc = session(&mut image);
            let paddr = allocate(&mut disc, LAYOUT.spaceman, INITIAL_XID).expect("allocate");
            free(&mut disc, LAYOUT.spaceman, INITIAL_XID, paddr).expect("free");
        }
        let after = verify(&image);
        assert_eq!(after.free_block_count, before.free_block_count);
    }

    #[test]
    fn freeing_a_block_that_is_not_allocated_is_rejected() {
        let mut image = open();
        let mut disc = session(&mut image);
        let result = free(&mut disc, LAYOUT.spaceman, INITIAL_XID, LAYOUT.free_from);
        assert!(matches!(result, Err(SpacemanError::NotAllocated { .. })));
    }

    #[test]
    fn freeing_an_address_outside_every_chunk_is_rejected() {
        let mut image = open();
        let mut disc = session(&mut image);
        let result = free(&mut disc, LAYOUT.spaceman, INITIAL_XID, BLOCK_COUNT + 100);
        assert!(matches!(result, Err(SpacemanError::NoSuchChunk { .. })));
    }
}
