#[cfg(test)]
mod tests {
    use crate::apfs_verify::{
        self, BlockSource, NX_MAGIC, OBJ_PHYSICAL, OBJ_TYPE_MASK, TYPE_NX_SUPERBLOCK, VerifyError,
    };
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    const CAPTURE_MAGIC: &[u8; 8] = &[0x4d, 0x58, 0x41, 0x50, 0x46, 0x53, 0x46, 0x58];
    const CAPTURE_HEADER_BYTES: usize = 28;

    struct Recording {
        file: File,
        block_size: u32,
        seen: BTreeMap<u64, Vec<u8>>,
    }

    impl BlockSource for Recording {
        fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
            if let Some(cached) = self.seen.get(&index) {
                into.copy_from_slice(cached);
                return Ok(());
            }
            let at = index
                .checked_mul(self.block_size as u64)
                .ok_or(VerifyError::BlockOutOfRange { index })?;
            self.file
                .seek(SeekFrom::Start(at))
                .map_err(|_| VerifyError::BlockOutOfRange { index })?;
            self.file
                .read_exact(into)
                .map_err(|_| VerifyError::BlockOutOfRange { index })?;
            self.seen.insert(index, into.to_vec());
            Ok(())
        }
    }

    #[test]
    #[ignore = "regenerates a corpus fixture from a real raw container named by \
                APFS_CORPUS_SOURCE into APFS_CORPUS_DEST; run manually"]
    fn regenerate_corpus_fixture() {
        let source = std::env::var("APFS_CORPUS_SOURCE")
            .expect("set APFS_CORPUS_SOURCE to a raw APFS container file");
        let dest = std::env::var("APFS_CORPUS_DEST")
            .expect("set APFS_CORPUS_DEST to the fixtures/*.blocks path to write");
        let block_size = 4096u32;
        let file = File::open(&source).unwrap_or_else(|e| panic!("open {source}: {e}"));
        let len = file
            .metadata()
            .unwrap_or_else(|e| panic!("metadata {source}: {e}"))
            .len();
        assert_eq!(
            len % block_size as u64,
            0,
            "{source} is not a whole number of {block_size}-byte blocks"
        );
        let mut recording = Recording {
            file,
            block_size,
            seen: BTreeMap::new(),
        };
        let verified = apfs_verify::verify_container(&mut recording).unwrap_or_else(|e| {
            panic!("{source} does not itself verify, refusing to capture it: {e}")
        });
        eprintln!(
            "{source}: xid={} objects_checked={} volumes={} blocks_captured={}",
            verified.xid,
            verified.objects_checked,
            verified.volumes.len(),
            recording.seen.len()
        );

        let mut out = Vec::with_capacity(
            CAPTURE_HEADER_BYTES + recording.seen.len() * (8 + block_size as usize),
        );
        out.extend_from_slice(CAPTURE_MAGIC);
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&block_size.to_le_bytes());
        out.extend_from_slice(&(len / block_size as u64).to_le_bytes());
        out.extend_from_slice(&(recording.seen.len() as u32).to_le_bytes());
        for (index, bytes) in &recording.seen {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(bytes);
        }
        std::fs::write(&dest, &out).unwrap_or_else(|e| panic!("write {dest}: {e}"));
    }

    struct Fixture {
        block_count: u64,
        block_size: usize,
        blocks: Vec<(u64, Vec<u8>)>,
    }

    impl Fixture {
        fn load(path: &str) -> Self {
            let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
            assert_eq!(&bytes[..8], CAPTURE_MAGIC, "{path}: capture magic");
            assert_eq!(u32_at(&bytes, 8), 1, "{path}: capture version");
            let block_size = u32_at(&bytes, 12) as usize;
            let block_count = u64_at(&bytes, 16);
            let records = u32_at(&bytes, 24) as usize;
            let mut blocks = Vec::with_capacity(records);
            let mut at = CAPTURE_HEADER_BYTES;
            for _ in 0..records {
                let index = u64_at(&bytes, at);
                at += 8;
                blocks.push((index, bytes[at..at + block_size].to_vec()));
                at += block_size;
            }
            assert_eq!(at, bytes.len(), "{path}: capture has trailing bytes");
            assert!(
                blocks.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "{path}: capture is not sorted by address"
            );
            Self {
                block_count,
                block_size,
                blocks,
            }
        }

        fn slot(&self, paddr: u64) -> usize {
            self.blocks
                .binary_search_by_key(&paddr, |(index, _)| *index)
                .unwrap_or_else(|_| panic!("block {paddr} is not in this fixture's capture"))
        }

        fn block(&self, paddr: u64) -> &[u8] {
            &self.blocks[self.slot(paddr)].1
        }

        fn edit(&mut self, paddr: u64, edit: impl FnOnce(&mut [u8])) {
            let slot = self.slot(paddr);
            let block = &mut self.blocks[slot].1;
            edit(block);
            reseal(block);
        }

        fn edit_leave_checksum_wrong(&mut self, paddr: u64, edit: impl FnOnce(&mut [u8])) {
            let slot = self.slot(paddr);
            edit(&mut self.blocks[slot].1);
        }

        fn verify(&mut self) -> Result<apfs_verify::VerifiedContainer, VerifyError> {
            apfs_verify::verify_container(self)
        }
    }

    impl BlockSource for Fixture {
        fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
            assert_eq!(
                into.len(),
                self.block_size,
                "caller's block size disagrees with the capture"
            );
            if index >= self.block_count {
                return Err(VerifyError::BlockOutOfRange { index });
            }
            match self
                .blocks
                .binary_search_by_key(&index, |(paddr, _)| *paddr)
            {
                Ok(slot) => into.copy_from_slice(&self.blocks[slot].1),
                Err(_) => into.fill(0),
            }
            Ok(())
        }
    }

    fn reseal(block: &mut [u8]) {
        let mut low: u64 = 0;
        let mut high: u64 = 0;
        for word in block[8..].as_chunks::<4>().0 {
            low = (low + u32::from_le_bytes(*word) as u64) % 0xFFFF_FFFF;
            high = (high + low) % 0xFFFF_FFFF;
        }
        let first = 0xFFFF_FFFF - ((low + high) % 0xFFFF_FFFF);
        let second = 0xFFFF_FFFF - ((low + first) % 0xFFFF_FFFF);
        block[0..8].copy_from_slice(&((second << 32) | first).to_le_bytes());
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    fn mounted_superblock(fixture: &Fixture) -> u64 {
        let zero = fixture.block(0);
        let descriptor_base = u64_at(zero, 0x70);
        let descriptor_blocks = u32_at(zero, 0x68) as u64;
        let mut best: Option<(u64, u64)> = None;
        for slot in 0..descriptor_blocks {
            let paddr = descriptor_base + slot;
            if fixture.slot(paddr) >= fixture.blocks.len() {
                continue;
            }
            let block = fixture.block(paddr);
            if u32_at(block, 0x18) & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
                continue;
            }
            if u32_at(block, 0x20) != NX_MAGIC {
                continue;
            }
            let xid = u64_at(block, 0x10);
            if best.is_none_or(|(best_xid, _)| xid > best_xid) {
                best = Some((xid, paddr));
            }
        }
        best.expect("a captured container must carry a mountable checkpoint")
            .1
    }

    fn mounted_spaceman_paddr(fixture: &Fixture, superblock: u64) -> u64 {
        let sb = fixture.block(superblock);
        let sm_oid = u64_at(sb, 0x98);
        let sb_xid = u64_at(sb, 0x10);
        let checkpoint_map = fixture
            .blocks
            .iter()
            .find(|(_, bytes)| {
                u32_at(bytes, 0x18) == (OBJ_PHYSICAL | 0x0C)
                    && u64_at(bytes, 0x10) == sb_xid
                    && (0..u32_at(bytes, 0x24) as usize)
                        .any(|i| u64_at(bytes, 0x28 + i * 40 + 24) == sm_oid)
            })
            .map(|(_, bytes)| bytes)
            .expect("the mounted checkpoint's space manager mapping must be in the capture");
        let count = u32_at(checkpoint_map, 0x24) as usize;
        (0..count)
            .find(|&i| u64_at(checkpoint_map, 0x28 + i * 40 + 24) == sm_oid)
            .map(|i| u64_at(checkpoint_map, 0x28 + i * 40 + 32))
            .expect("just matched above")
    }

    #[test]
    fn a_single_unsealed_volume_container_verifies_end_to_end() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let verified = fixture.verify().expect("verify");
        assert_eq!(verified.volumes.len(), 1);
        assert!(!verified.volumes[0].sealed);
        assert!(verified.volumes[0].root.is_some());
    }

    #[test]
    fn a_case_sensitive_volume_container_verifies_end_to_end() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-case-sensitive.blocks");
        let verified = fixture.verify().expect("verify");
        assert_eq!(verified.volumes.len(), 1);
        assert_eq!(verified.volumes[0].incompatible_features & 0x1, 0);
        assert_eq!(verified.volumes[0].incompatible_features & 0x8, 0x8);
    }

    #[test]
    fn a_four_volume_container_with_distinct_roles_verifies_end_to_end() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-multi-role.blocks");
        let verified = fixture.verify().expect("verify");
        assert_eq!(verified.volumes.len(), 4);
        let mut roles: Vec<u16> = verified.volumes.iter().map(|v| v.role).collect();
        roles.sort_unstable();
        assert_eq!(roles, vec![0x1, 0x4, 0x8, 0x10]);
    }

    #[test]
    fn a_volume_with_extended_attributes_and_hard_links_verifies_end_to_end() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-xattr.blocks");
        let verified = fixture.verify().expect("verify");
        let root = verified.volumes[0].root.as_ref().expect("root");
        assert!(
            root.record_count >= 10,
            "expected the xattr/sibling records too"
        );
    }

    #[test]
    fn a_container_forcing_chunk_info_address_blocks_verifies_end_to_end() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-cab.blocks");
        let verified = fixture.verify().expect("verify");
        assert_eq!(verified.block_count, 1u64 << 31);
    }

    #[test]
    fn a_volume_with_thousands_of_files_walks_its_whole_catalog() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-many-files.blocks");
        let verified = fixture.verify().expect("verify");
        assert!(
            verified.objects_checked > 100,
            "objects_checked={} is too low for a fully walked multi-level tree",
            verified.objects_checked
        );
        let root = verified.volumes[0].root.as_ref().expect("root");
        assert!(root.record_count > 1000, "expected every file's records");
    }

    #[test]
    fn a_bad_checksum_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        let spaceman_oid = u64_at(fixture.block(superblock), 0x98);
        let spaceman_paddr = fixture
            .blocks
            .iter()
            .find(|(_, bytes)| {
                u64_at(bytes, 8) == spaceman_oid && u32_at(bytes, 0x18) & OBJ_TYPE_MASK == 0x05
            })
            .map(|(paddr, _)| *paddr)
            .expect("space manager must be in the capture");
        fixture.edit_leave_checksum_wrong(spaceman_paddr, |block| block[100] ^= 0xFF);
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::BadChecksum {
                paddr: spaceman_paddr
            })
        );
    }

    #[test]
    fn a_wrong_object_type_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        let reaper_oid = u64_at(fixture.block(superblock), 0xA8);
        let checkpoint_map_paddr = fixture
            .blocks
            .iter()
            .find(|(_, bytes)| {
                u32_at(bytes, 0x18) == (OBJ_PHYSICAL | 0x0C)
                    && u64_at(bytes, 0x10) == u64_at(fixture.block(superblock), 0x10)
                    && (0..u32_at(bytes, 0x24) as usize)
                        .any(|i| u64_at(bytes, 0x28 + i * 40 + 24) == reaper_oid)
            })
            .map(|(paddr, _)| *paddr)
            .expect("the mounted checkpoint's reaper mapping must be in the capture");
        let reaper_paddr = {
            let bytes = fixture.block(checkpoint_map_paddr);
            let count = u32_at(bytes, 0x24) as usize;
            (0..count)
                .find(|&i| u64_at(bytes, 0x28 + i * 40 + 24) == reaper_oid)
                .map(|i| u64_at(bytes, 0x28 + i * 40 + 32))
                .expect("just matched above")
        };
        fixture.edit(checkpoint_map_paddr, |block| {
            let count = u32_at(block, 0x24) as usize;
            for i in 0..count {
                let at = 0x28 + i * 40;
                if u64_at(block, at + 24) == reaper_oid {
                    let mangled = (u32_at(block, at) & !OBJ_TYPE_MASK) | 0x99;
                    block[at..at + 4].copy_from_slice(&mangled.to_le_bytes());
                }
            }
        });
        fixture.edit(reaper_paddr, |block| {
            let mangled = (u32_at(block, 0x18) & !OBJ_TYPE_MASK) | 0x99;
            block[0x18..0x1C].copy_from_slice(&mangled.to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::ObjectMismatch {
                paddr: reaper_paddr,
                field: "object type",
                expected: 0x11,
                observed: 0x99,
            })
        );
    }

    #[test]
    fn a_mismatched_checkpoint_descriptor_index_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        let real_index = u32_at(fixture.block(superblock), 0x88);
        fixture.edit(superblock, |block| {
            block[0x88..0x8C].copy_from_slice(&(real_index + 1).to_le_bytes());
        });
        let error = fixture.verify().expect_err("desc index must disagree");
        match error {
            VerifyError::FieldMismatch { what, observed, .. } => {
                assert_eq!(what, "nx_xp_desc_index");
                assert_eq!(observed, (real_index + 1) as u64);
            }
            other => panic!("expected a checkpoint descriptor index mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_bad_ephemeral_info_version_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        fixture.edit(superblock, |block| {
            let word0 = u64_at(block, 0x520);
            let mangled = (word0 & !0xF) | 0x2;
            block[0x520..0x528].copy_from_slice(&mangled.to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldMismatch {
                what: "nx_ephemeral_info[0] version",
                expected: 1,
                observed: 2,
            })
        );
    }

    #[test]
    fn a_bad_ephemeral_info_minimum_block_count_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        fixture.edit(superblock, |block| {
            let word0 = u64_at(block, 0x520);
            let mangled = (word0 & 0xFFFF_FFFF) | (5u64 << 32);
            block[0x520..0x528].copy_from_slice(&mangled.to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldOutOfRange {
                what: "nx_ephemeral_info[0] minimum block count per structure",
                observed: 5,
            })
        );
    }

    #[test]
    fn a_wrong_max_file_systems_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        fixture.edit(superblock, |block| {
            block[0xB4..0xB8].copy_from_slice(&2u32.to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldMismatch {
                what: "nx_max_file_systems",
                expected: 1,
                observed: 2,
            })
        );
    }

    #[test]
    fn an_unaligned_internal_pool_free_chain_offset_on_a_real_container_is_caught() {
        // fsck_apfs -n accepts a misaligned sm_ip_bm_free_next_offset; the kernel mount path does not.
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        let spaceman = mounted_spaceman_paddr(&fixture, superblock);
        let real_next_offset = u32_at(fixture.block(spaceman), 0x14C);
        fixture.edit(spaceman, |block| {
            block[0x14C..0x150].copy_from_slice(&(real_next_offset - 6).to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldMismatch {
                what: "sm_ip_bm_free_next_offset",
                expected: real_next_offset as u64,
                observed: (real_next_offset - 6) as u64,
            })
        );
    }

    #[test]
    fn a_misaligned_chunk_info_address_array_offset_on_a_real_container_is_caught() {
        // sm_dev[SD_MAIN].addr_offset is 8-byte aligned immediately after the ip ring's free-chain array.
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        let spaceman = mounted_spaceman_paddr(&fixture, superblock);
        let real_addr_offset = u32_at(fixture.block(spaceman), 0x50);
        fixture.edit(spaceman, |block| {
            block[0x50..0x54].copy_from_slice(&(real_addr_offset - 6).to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldMismatch {
                what: "sm_dev[SD_MAIN].addr_offset",
                expected: real_addr_offset as u64,
                observed: (real_addr_offset - 6) as u64,
            })
        );
    }

    #[test]
    fn a_truncated_checkpoint_descriptor_ring_on_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-single-volume.blocks");
        let superblock = mounted_superblock(&fixture);
        fixture.edit(superblock, |block| {
            block[0x68..0x6C].copy_from_slice(&2u32.to_le_bytes());
        });
        assert_eq!(
            fixture.verify(),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint descriptor ring size",
                observed: 2,
            })
        );
    }

    #[test]
    fn a_cycle_in_the_filesystem_tree_of_a_real_container_is_caught() {
        let mut fixture = Fixture::load("fixtures/apfs-corpus-many-files.blocks");

        let is_fs_index_node = |bytes: &[u8]| -> bool {
            u32_at(bytes, 0x18) & OBJ_TYPE_MASK == 0x03
                && u32_at(bytes, 0x1C) & OBJ_TYPE_MASK == 0x0E
                && u16_at(bytes, 0x22) == 1
                && u16_at(bytes, 0x20) & 0x2 == 0
        };
        let index_node = fixture
            .blocks
            .iter()
            .find(|(_, bytes)| is_fs_index_node(bytes))
            .map(|(paddr, _)| *paddr)
            .expect("this fixture's tree has an index level");
        assert!(
            u32_at(fixture.block(index_node), 0x24) >= 2,
            "need at least two of the index node's own records to collide between"
        );

        let child_value_range = |bytes: &[u8], entry_index: usize| -> std::ops::Range<usize> {
            let flags = u16_at(bytes, 0x20);
            assert_eq!(flags & 0x4, 0, "fixed-kv node not expected here");
            let toc_off = u16_at(bytes, 0x28) as usize;
            let value_end = bytes.len() - if flags & 0x1 != 0 { 40 } else { 0 };
            let at = 56 + toc_off + entry_index * 8;
            let value_off = u16_at(bytes, at + 4) as usize;
            let value_len = u16_at(bytes, at + 6) as usize;
            let value_at = value_end - value_off;
            value_at..value_at + value_len
        };

        let entry_0_child = {
            let bytes = fixture.block(index_node);
            let range = child_value_range(bytes, 0);
            u64_at(bytes, range.start)
        };
        fixture.edit(index_node, |block| {
            let range = child_value_range(block, 1);
            block[range.clone()].copy_from_slice(&entry_0_child.to_le_bytes()[..range.len()]);
        });

        let error = fixture
            .verify()
            .expect_err("a genuine cycle must be refused");
        match error {
            VerifyError::NodeMalformed { reason, .. } => {
                assert_eq!(reason, "filesystem tree node was reached more than once");
            }
            other => panic!("expected the leaf to be refused as reached twice, got {other:?}"),
        }
    }
}
