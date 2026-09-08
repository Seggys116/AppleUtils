use std::fmt;
use std::io::{Read, Seek, SeekFrom};

pub(crate) const NX_MAGIC: u32 = 0x4253_584E;
pub(crate) const APFS_MAGIC: u32 = 0x4253_5041;

pub(crate) const OBJ_STORAGE_MASK: u32 = 0xC000_0000;
pub(crate) const OBJ_VIRTUAL: u32 = 0x0000_0000;
const OBJ_EPHEMERAL: u32 = 0x8000_0000;
pub(crate) const OBJ_PHYSICAL: u32 = 0x4000_0000;
pub(crate) const OBJ_TYPE_MASK: u32 = 0x0000_FFFF;

pub(crate) const TYPE_NX_SUPERBLOCK: u32 = 0x01;
pub(crate) const TYPE_BTREE: u32 = 0x02;
pub(crate) const TYPE_BTREE_NODE: u32 = 0x03;
const TYPE_SPACEMAN: u32 = 0x05;
const TYPE_SPACEMAN_CAB: u32 = 0x06;
const TYPE_SPACEMAN_CIB: u32 = 0x07;
const TYPE_OMAP: u32 = 0x0B;
const TYPE_CHECKPOINT_MAP: u32 = 0x0C;
pub(crate) const TYPE_FS: u32 = 0x0D;
const TYPE_NX_REAPER: u32 = 0x11;
const TYPE_NX_REAP_LIST: u32 = 0x12;
const TYPE_INTEGRITY_META: u32 = 0x1E;

const BTNODE_ROOT: u16 = 0x1;
const BTNODE_LEAF: u16 = 0x2;
const BTNODE_FIXED_KV_SIZE: u16 = 0x4;
const BTNODE_NOHEADER: u16 = 0x10;
const BTREE_INFO_BYTES: usize = 40;
const BTNODE_TOC_BASE: usize = 56;
const BTOFF_INVALID: u16 = 0xFFFF;

const CHECKPOINT_MAPPING_BYTES: usize = 40;
const CHUNK_INFO_BYTES: usize = 32;
const SPACEMAN_STRUCT_SIZE: u32 = 2520;

pub(crate) const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x20;

const APSB_INTEGRITY_META_OID_OFFSET: usize = 0x400;

const APSB_SNAP_META_TREE_OID_OFFSET: usize = 0x98;

const APSB_NUM_SNAPSHOTS_OFFSET: usize = 0xD8;

// XNU reads apfs_root_to_xid as the booting xid; zero selects role 0 and always requires authentication.
const APSB_ROOT_TO_XID_OFFSET: usize = 0x3C8;

const APSB_VOLUME_GROUP_OFFSET: usize = 0x3F0;

const NX_MIN_CHECKPOINT_RING_BLOCKS: u32 = 8;

const NX_MIN_CHECKPOINT_SEGMENT_BLOCKS: u32 = 2;

const NX_EFI_JUMPSTART_OFFSET: usize = 0x4F8;

const NX_FUSION_UUID_OFFSET: usize = 0x500;

const NX_KEYLOCKER_OFFSET: usize = 0x510;

const NX_EPHEMERAL_INFO_OFFSET: usize = 0x520;

const NX_FUSION_MT_OID_OFFSET: usize = 0x548;
const NX_FUSION_WBC_OID_OFFSET: usize = 0x550;
const NX_FUSION_WBC_OFFSET: usize = 0x558;

const NX_EPH_INFO_VERSION: u64 = 1;

const NX_EPH_INFO_STRUCTS_PER_FS: u64 = 4;

// fsck_apfs checks this against a runtime bound, not a literal; real containers carry only 4 (64 MiB) or 8 (512 MiB up).
const NX_EPH_INFO_MIN_BLOCK_COUNTS: [u64; 2] = [4, 8];

const IM_VERSION_OFFSET: usize = 0x20;
const IM_FLAGS_OFFSET: usize = 0x24;
const IM_HASH_TYPE_OFFSET: usize = 0x28;
const IM_ROOT_HASH_OFFSET_OFFSET: usize = 0x2C;
const IM_BROKEN_XID_OFFSET: usize = 0x30;

// A seal the filesystem invalidated: the volume still carries a root hash it no longer matches.
const APFS_SEAL_BROKEN: u32 = 0x1;

const APFS_HASH_MAX_SIZE: usize = 64;

const SEAL_HASH_LENGTHS: [(u32, &str, usize); 10] = [
    (1, "sha256", 32),
    (2, "sha512_256", 32),
    (3, "sha384", 48),
    (4, "sha512", 64),
    (5, "sha3_256", 32),
    (6, "sha3_384", 48),
    (7, "sha3_512", 64),
    (8, "sha3_256_4k", 32),
    (9, "sha3_384_4k", 48),
    (10, "sha3_512_4k", 64),
];

pub fn seal_hash_type(hash_type: u32) -> Option<(&'static str, usize)> {
    SEAL_HASH_LENGTHS
        .iter()
        .find(|(number, _, _)| *number == hash_type)
        .map(|(_, name, length)| (*name, *length))
}

pub fn decode_volume_seal(
    volume_oid: u64,
    oid: u64,
    paddr: u64,
    bytes: &[u8],
) -> Result<VolumeSeal, VerifyError> {
    if bytes.len() < IM_BROKEN_XID_OFFSET + 8 {
        return Err(VerifyError::FieldOutOfRange {
            what: "the integrity metadata object length",
            observed: bytes.len() as u64,
        });
    }

    let hash_type = u32_at(bytes, IM_HASH_TYPE_OFFSET);
    let Some((hash_name, hash_length)) =
        seal_hash_type(hash_type).filter(|(_, length)| *length <= APFS_HASH_MAX_SIZE)
    else {
        return Err(VerifyError::UnknownSealHashType {
            volume: volume_oid,
            hash_type,
        });
    };

    let root_hash_offset = u32_at(bytes, IM_ROOT_HASH_OFFSET_OFFSET);
    let start = root_hash_offset as usize;
    let end = start
        .checked_add(hash_length)
        .filter(|end| *end <= bytes.len())
        .ok_or(VerifyError::SealRootHashOutOfRange {
            paddr,
            offset: root_hash_offset,
            length: hash_length,
        })?;

    let flags = u32_at(bytes, IM_FLAGS_OFFSET);
    Ok(VolumeSeal {
        oid,
        paddr,
        version: u32_at(bytes, IM_VERSION_OFFSET),
        flags,
        broken: flags & APFS_SEAL_BROKEN != 0,
        broken_xid: u64_at(bytes, IM_BROKEN_XID_OFFSET),
        hash_type,
        hash_name,
        root_hash_offset,
        root_hash: bytes[start..end].to_vec(),
    })
}

const J_SNAP_METADATA: u64 = 1;
pub(crate) const J_INODE: u64 = 3;
pub(crate) const J_XATTR: u64 = 4;
const J_SIBLING_LINK: u64 = 5;
pub(crate) const J_CRYPTO_STATE: u64 = 7;
pub(crate) const J_FILE_EXTENT: u64 = 8;
pub(crate) const J_DIR_REC: u64 = 9;
const J_SNAP_NAME: u64 = 11;

const ROOT_DIR_PARENT: u64 = 1;
pub(crate) const ROOT_DIR_INO_NUM: u64 = 2;
const PRIV_DIR_INO_NUM: u64 = 3;

const APFS_INCOMPAT_CASE_INSENSITIVE: u64 = 0x1;
const APFS_INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 0x8;

const J_DREC_LEN_MASK: u32 = 0x0000_03FF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DrecKeyLayout {
    Plain,
    Hashed,
}

impl DrecKeyLayout {
    pub(crate) fn of(incompatible_features: u64) -> Self {
        let hashing = APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_NORMALIZATION_INSENSITIVE;
        if incompatible_features & hashing != 0 {
            Self::Hashed
        } else {
            Self::Plain
        }
    }

    pub(crate) fn name_offset(self) -> usize {
        match self {
            Self::Plain => 10,
            Self::Hashed => 12,
        }
    }

    pub(crate) fn name_length(self, key: &[u8]) -> Option<usize> {
        match self {
            Self::Plain => (key.len() >= 10).then(|| u16_at(key, 8) as usize),
            Self::Hashed => (key.len() >= 12).then(|| (u32_at(key, 8) & J_DREC_LEN_MASK) as usize),
        }
    }

    fn sort_prefix(self, key: &[u8]) -> u32 {
        match self {
            Self::Plain => 0,
            Self::Hashed => {
                if key.len() >= 12 {
                    u32_at(key, 8)
                } else {
                    0
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RecordTail {
    Number(u64),
    Named { prefix: u32, name: Vec<u8> },
    Bytes(Vec<u8>),
}

impl RecordTail {
    fn of(kind: u64, key: &[u8], layout: DrecKeyLayout) -> Self {
        match kind {
            J_DIR_REC if key.len() >= layout.name_offset() => Self::Named {
                prefix: layout.sort_prefix(key),
                name: key[layout.name_offset()..].to_vec(),
            },
            J_XATTR | J_SNAP_NAME if key.len() >= 10 => Self::Named {
                prefix: 0,
                name: key[10..].to_vec(),
            },
            J_SIBLING_LINK | J_FILE_EXTENT if key.len() >= 16 => Self::Number(u64_at(key, 8)),
            _ => Self::Bytes(key[8.min(key.len())..].to_vec()),
        }
    }
}

pub(crate) const MAX_REASONABLE_BLOCKS: u64 = 1 << 40;

pub trait BlockSource {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError>;

    fn read_run(&mut self, index: u64, blocks: usize, into: &mut [u8]) -> Result<(), VerifyError> {
        if blocks == 0 {
            return Ok(());
        }
        if !into.len().is_multiple_of(blocks) {
            return Err(VerifyError::BlockOutOfRange { index });
        }
        let block_size = into.len() / blocks;
        for offset in 0..blocks {
            let at = offset * block_size;
            self.read_block(
                index
                    .checked_add(offset as u64)
                    .ok_or(VerifyError::BlockOutOfRange { index })?,
                &mut into[at..at + block_size],
            )?;
        }
        Ok(())
    }
}

pub struct SliceBlocks<'a> {
    bytes: &'a [u8],
    block_size: usize,
}

impl<'a> SliceBlocks<'a> {
    pub fn new(bytes: &'a [u8], block_size: u32) -> Self {
        Self {
            bytes,
            block_size: block_size as usize,
        }
    }
}

impl BlockSource for SliceBlocks<'_> {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
        let at = index
            .checked_mul(self.block_size as u64)
            .and_then(|at| usize::try_from(at).ok())
            .ok_or(VerifyError::BlockOutOfRange { index })?;
        let end = at + self.block_size;
        if end > self.bytes.len() {
            return Err(VerifyError::BlockOutOfRange { index });
        }
        into.copy_from_slice(&self.bytes[at..end]);
        Ok(())
    }
}

pub struct ReaderBlocks<R> {
    reader: R,
    base: u64,
    block_size: u64,
}

impl<R: Read + Seek> ReaderBlocks<R> {
    pub fn new(reader: R, base: u64, block_size: u32) -> Self {
        Self {
            reader,
            base,
            block_size: block_size as u64,
        }
    }
}

impl<R: Read + Seek> BlockSource for ReaderBlocks<R> {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
        let at = index
            .checked_mul(self.block_size)
            .and_then(|at| at.checked_add(self.base))
            .ok_or(VerifyError::BlockOutOfRange { index })?;
        self.reader
            .seek(SeekFrom::Start(at))
            .map_err(|_| VerifyError::BlockOutOfRange { index })?;
        self.reader
            .read_exact(into)
            .map_err(|_| VerifyError::BlockOutOfRange { index })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedContainer {
    pub block_size: u32,
    pub block_count: u64,
    pub uuid: [u8; 16],
    pub xid: u64,
    pub superblock_paddr: u64,
    pub max_file_systems: u32,
    pub free_block_count: u64,
    pub ephemeral: Vec<(u64, u64, u32)>,
    pub volumes: Vec<VerifiedVolume>,
    pub objects_checked: usize,
    pub blocks_in_use: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedVolume {
    pub oid: u64,
    pub paddr: u64,
    pub fs_index: u32,
    pub name: String,
    pub role: u16,
    pub uuid: [u8; 16],
    pub sealed: bool,
    pub incompatible_features: u64,
    pub read_only_compatible_features: u64,
    pub reserve_block_count: u64,
    pub quota_block_count: u64,
    pub fs_flags: u64,
    pub next_obj_id: u64,
    pub fs_tree_oid: u64,
    pub fs_tree_paddr: u64,
    pub extentref_tree_paddr: u64,
    pub snap_meta_tree_paddr: u64,
    pub root: Option<VerifiedFsRoot>,
    pub seal: Option<VolumeSeal>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSeal {
    pub oid: u64,
    pub paddr: u64,
    pub version: u32,
    pub flags: u32,
    pub broken: bool,
    pub broken_xid: u64,
    pub hash_type: u32,
    pub hash_name: &'static str,
    pub root_hash_offset: u32,
    pub root_hash: Vec<u8>,
}

impl VolumeSeal {
    pub fn matches_digest(&self, digest: &[u8]) -> bool {
        self.root_hash == digest
    }

    pub fn root_hash_hex(&self) -> String {
        let mut out = String::with_capacity(self.root_hash.len() * 2);
        for byte in &self.root_hash {
            out.push_str(&format!("{byte:02X}"));
        }
        out
    }

    // The kernel derives this same name from the forwarded auth blob: the prefix plus the root hash as UPPERCASE hex.
    pub fn root_snapshot_name(&self) -> String {
        format!("{ROOT_SNAPSHOT_PREFIX}{}", self.root_hash_hex())
    }

    // authenticate_root_hash compares words 0 and 2 against the volume's own integrity_meta_phys_t, so both come from the seal.
    pub fn to_forwarded_root_hash_blob(&self) -> Vec<u8> {
        let mut blob = vec![0u8; FORWARDED_ROOT_HASH_BLOB_BYTES];
        blob[0..4].copy_from_slice(&self.version.to_le_bytes());
        blob[8..12].copy_from_slice(&self.hash_type.to_le_bytes());
        let digest_len = u32::try_from(self.root_hash.len()).unwrap_or(u32::MAX);
        blob[12..16].copy_from_slice(&digest_len.to_le_bytes());
        let end = FORWARDED_ROOT_HASH_DIGEST_OFFSET.saturating_add(self.root_hash.len());
        if end <= blob.len() {
            blob[FORWARDED_ROOT_HASH_DIGEST_OFFSET..end].copy_from_slice(&self.root_hash);
        }
        blob
    }
}

pub const ROOT_SNAPSHOT_PREFIX: &str = "com.apple.os.update-";

pub const FORWARDED_ROOT_HASH_BLOB_BYTES: usize = 0xD0;

// Digest slot chosen on the container block size: +0x10 for 4096, +0x50 for 8192, +0x90 for 16384.
const FORWARDED_ROOT_HASH_DIGEST_OFFSET: usize = 0x10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFsRoot {
    pub record_count: usize,
    pub entries: Vec<(String, u64)>,
    pub inodes: Vec<u64>,
    pub root_dir_mode: Option<u16>,
    pub private_dir_mode: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    BlockOutOfRange {
        index: u64,
    },
    BadMagic {
        paddr: u64,
        observed: u32,
    },
    BadChecksum {
        paddr: u64,
    },
    UnsupportedBlockSize {
        block_size: u32,
    },
    ImplausibleBlockCount {
        block_count: u64,
    },
    ObjectMismatch {
        paddr: u64,
        field: &'static str,
        expected: u64,
        observed: u64,
    },
    NoCheckpoint,
    UnmappedEphemeralOid {
        oid: u64,
    },
    MappingOutsideDataArea {
        oid: u64,
        paddr: u64,
    },
    RegionOutOfBounds {
        what: &'static str,
        first: u64,
        count: u64,
    },
    RegionOverlap {
        earlier: &'static str,
        later: &'static str,
    },
    ChunkFreeCountMismatch {
        chunk_addr: u64,
        recorded: u32,
        counted: u32,
    },
    ChunkCoverage {
        covered: u64,
        block_count: u64,
    },
    FreeCountMismatch {
        recorded: u64,
        counted: u64,
    },
    BlockNotAllocated {
        paddr: u64,
        what: &'static str,
    },
    RingBroken {
        reason: &'static str,
    },
    ReapListBroken {
        reason: &'static str,
    },
    NodeMalformed {
        paddr: u64,
        reason: &'static str,
    },
    UnmappedVirtualOid {
        oid: u64,
    },
    RecordsOutOfOrder {
        paddr: u64,
        index: usize,
    },
    RootDirectoryMissing {
        volume: u64,
        reason: &'static str,
    },
    FieldOutOfRange {
        what: &'static str,
        observed: u64,
    },
    UnknownSealHashType {
        volume: u64,
        hash_type: u32,
    },
    SealRootHashOutOfRange {
        paddr: u64,
        offset: u32,
        length: usize,
    },
    FieldMismatch {
        what: &'static str,
        expected: u64,
        observed: u64,
    },
    AddressOutsideInternalPool {
        paddr: u64,
        what: &'static str,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockOutOfRange { index } => write!(f, "block {index} is outside the container"),
            Self::BadMagic { paddr, observed } => {
                write!(
                    f,
                    "block {paddr} has magic {observed:#010x}, not a container superblock"
                )
            }
            Self::BadChecksum { paddr } => write!(f, "block {paddr} fails its Fletcher-64 check"),
            Self::UnsupportedBlockSize { block_size } => {
                write!(
                    f,
                    "block size {block_size} is not a supported APFS block size"
                )
            }
            Self::ImplausibleBlockCount { block_count } => {
                write!(f, "block count {block_count} is implausible")
            }
            Self::ObjectMismatch {
                paddr,
                field,
                expected,
                observed,
            } => write!(
                f,
                "block {paddr} reports {field} {observed}, but {expected} was expected"
            ),
            Self::NoCheckpoint => write!(f, "no container superblock in the descriptor area"),
            Self::UnmappedEphemeralOid { oid } => {
                write!(f, "ephemeral object {oid} is not in the checkpoint map")
            }
            Self::MappingOutsideDataArea { oid, paddr } => write!(
                f,
                "ephemeral object {oid} maps to block {paddr}, outside the checkpoint data area"
            ),
            Self::RegionOutOfBounds { what, first, count } => write!(
                f,
                "the {what} region of {count} blocks at {first} leaves the container"
            ),
            Self::RegionOverlap { earlier, later } => {
                write!(f, "the {earlier} and {later} regions overlap")
            }
            Self::ChunkFreeCountMismatch {
                chunk_addr,
                recorded,
                counted,
            } => write!(
                f,
                "chunk at {chunk_addr} records {recorded} free blocks, its bitmap has {counted}"
            ),
            Self::ChunkCoverage {
                covered,
                block_count,
            } => write!(
                f,
                "the chunks cover {covered} blocks of a {block_count}-block container"
            ),
            Self::FreeCountMismatch { recorded, counted } => write!(
                f,
                "the space manager records {recorded} free blocks, its chunks total {counted}"
            ),
            Self::BlockNotAllocated { paddr, what } => {
                write!(f, "block {paddr} holds the {what} but is marked free")
            }
            Self::RingBroken { reason } => {
                write!(f, "the internal pool bitmap ring is broken: {reason}")
            }
            Self::ReapListBroken { reason } => write!(f, "the reap list is broken: {reason}"),
            Self::NodeMalformed { paddr, reason } => {
                write!(f, "b-tree node at {paddr} is malformed: {reason}")
            }
            Self::UnmappedVirtualOid { oid } => {
                write!(f, "virtual object {oid} has no object map entry")
            }
            Self::RecordsOutOfOrder { paddr, index } => {
                write!(
                    f,
                    "records {index} and {} in node {paddr} are out of order",
                    index + 1
                )
            }
            Self::RootDirectoryMissing { volume, reason } => {
                write!(f, "volume {volume} has no usable root directory: {reason}")
            }
            Self::FieldOutOfRange { what, observed } => {
                write!(f, "{what} carries the unusable value {observed}")
            }
            Self::UnknownSealHashType { volume, hash_type } => write!(
                f,
                "volume {volume} is sealed with hash type {hash_type}, which this build cannot \
                 size, so its root hash cannot be read"
            ),
            Self::SealRootHashOutOfRange {
                paddr,
                offset,
                length,
            } => write!(
                f,
                "the integrity metadata at block {paddr} places a {length}-byte root hash at \
                 offset {offset}, outside the object"
            ),
            Self::FieldMismatch {
                what,
                expected,
                observed,
            } => write!(f, "{what} is {observed}, but {expected} was expected"),
            Self::AddressOutsideInternalPool { paddr, what } => write!(
                f,
                "block {paddr} holds the {what} but is outside the space manager's internal pool"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

pub(crate) fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

pub(crate) fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

pub(crate) fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

pub(crate) fn checksum_valid(block: &[u8]) -> bool {
    if block.len() < 8 || !block.len().is_multiple_of(4) {
        return false;
    }
    let mut low: u64 = 0;
    let mut high: u64 = 0;
    for word in block.chunks_exact(4) {
        low = (low + u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64) % 0xFFFF_FFFF;
        high = (high + low) % 0xFFFF_FFFF;
    }
    low == 0
}

pub(crate) struct Object {
    pub(crate) paddr: u64,
    pub(crate) bytes: Vec<u8>,
}

impl Object {
    pub(crate) fn oid(&self) -> u64 {
        u64_at(&self.bytes, 0x08)
    }
    pub(crate) fn xid(&self) -> u64 {
        u64_at(&self.bytes, 0x10)
    }
    pub(crate) fn o_type(&self) -> u32 {
        u32_at(&self.bytes, 0x18)
    }
    pub(crate) fn kind(&self) -> u32 {
        self.o_type() & OBJ_TYPE_MASK
    }
    pub(crate) fn storage(&self) -> u32 {
        self.o_type() & OBJ_STORAGE_MASK
    }
    pub(crate) fn subtype(&self) -> u32 {
        u32_at(&self.bytes, 0x1C)
    }
}

pub(crate) struct Verifier<'a> {
    pub(crate) source: &'a mut dyn BlockSource,
    pub(crate) block_size: usize,
    pub(crate) block_count: u64,
    pub(crate) objects_checked: usize,
    pub(crate) in_use: Vec<(u64, &'static str)>,
}

impl<'a> Verifier<'a> {
    pub(crate) fn read_checked(&mut self, paddr: u64) -> Result<Object, VerifyError> {
        if paddr >= self.block_count {
            return Err(VerifyError::BlockOutOfRange { index: paddr });
        }
        let mut bytes = vec![0u8; self.block_size];
        self.source.read_block(paddr, &mut bytes)?;
        if !checksum_valid(&bytes) {
            return Err(VerifyError::BadChecksum { paddr });
        }
        self.objects_checked += 1;
        Ok(Object { paddr, bytes })
    }

    pub(crate) fn read_checked_sized(
        &mut self,
        paddr: u64,
        blocks: usize,
    ) -> Result<Object, VerifyError> {
        if blocks == 0 {
            return Err(VerifyError::FieldOutOfRange {
                what: "object size in blocks",
                observed: 0,
            });
        }
        let end = paddr
            .checked_add(blocks as u64)
            .ok_or(VerifyError::BlockOutOfRange { index: paddr })?;
        if end > self.block_count {
            return Err(VerifyError::BlockOutOfRange { index: paddr });
        }
        let mut bytes = vec![0u8; self.block_size * blocks];
        self.source.read_run(paddr, blocks, &mut bytes)?;
        if !checksum_valid(&bytes) {
            return Err(VerifyError::BadChecksum { paddr });
        }
        self.objects_checked += 1;
        Ok(Object { paddr, bytes })
    }

    pub(crate) fn read_raw(&mut self, paddr: u64) -> Result<Vec<u8>, VerifyError> {
        if paddr >= self.block_count {
            return Err(VerifyError::BlockOutOfRange { index: paddr });
        }
        let mut bytes = vec![0u8; self.block_size];
        self.source.read_block(paddr, &mut bytes)?;
        Ok(bytes)
    }

    // A sealed volume's tree nodes carry an all-zero obj_phys: the seal's hash chain attests instead of Fletcher-64.
    pub(crate) fn read_headerless_node(&mut self, paddr: u64) -> Result<Object, VerifyError> {
        let bytes = self.read_raw(paddr)?;
        if bytes.len() < BTNODE_TOC_BASE {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "the block is shorter than a b-tree node header",
            });
        }
        if bytes[..0x20].iter().any(|byte| *byte != 0) {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "a headerless node was expected but the object header is not blank",
            });
        }
        if u16_at(&bytes, 0x20) & BTNODE_NOHEADER == 0 {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "the node does not declare itself headerless",
            });
        }
        self.note(paddr, "sealed filesystem tree node");
        Ok(Object { paddr, bytes })
    }

    pub(crate) fn note(&mut self, paddr: u64, what: &'static str) {
        self.in_use.push((paddr, what));
    }

    pub(crate) fn read_expecting(
        &mut self,
        paddr: u64,
        oid: Option<u64>,
        kind: u32,
        what: &'static str,
    ) -> Result<Object, VerifyError> {
        let object = self.read_checked(paddr)?;
        Self::check_header(&object, oid, kind)?;
        self.note(paddr, what);
        Ok(object)
    }

    pub(crate) fn read_expecting_sized(
        &mut self,
        paddr: u64,
        blocks: usize,
        oid: Option<u64>,
        kind: u32,
        what: &'static str,
    ) -> Result<Object, VerifyError> {
        let object = self.read_checked_sized(paddr, blocks)?;
        Self::check_header(&object, oid, kind)?;
        for offset in 0..blocks as u64 {
            self.note(paddr + offset, what);
        }
        Ok(object)
    }

    fn check_header(object: &Object, oid: Option<u64>, kind: u32) -> Result<(), VerifyError> {
        if object.kind() != kind {
            return Err(VerifyError::ObjectMismatch {
                paddr: object.paddr,
                field: "object type",
                expected: kind as u64,
                observed: object.kind() as u64,
            });
        }
        if let Some(oid) = oid
            && object.oid() != oid
        {
            return Err(VerifyError::ObjectMismatch {
                paddr: object.paddr,
                field: "object id",
                expected: oid,
                observed: object.oid(),
            });
        }
        Ok(())
    }
}

pub(crate) struct BTreeNode {
    pub(crate) paddr: u64,
    bytes: Vec<u8>,
    flags: u16,
    pub(crate) level: u16,
    pub(crate) nkeys: usize,
    key_base: usize,
    value_end: usize,
    toc: usize,
}

impl BTreeNode {
    pub(crate) fn decode(object: &Object, block_size: usize) -> Result<Self, VerifyError> {
        Self::decode_node(object, block_size, false)
    }

    pub(crate) fn decode_node(
        object: &Object,
        block_size: usize,
        headerless_permitted: bool,
    ) -> Result<Self, VerifyError> {
        let bytes = object.bytes.clone();
        let paddr = object.paddr;
        let flags = u16_at(&bytes, 0x20);
        if flags & BTNODE_NOHEADER != 0 && !headerless_permitted {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "headerless nodes belong to sealed volumes",
            });
        }
        let level = u16_at(&bytes, 0x22);
        let nkeys = u32_at(&bytes, 0x24) as usize;
        let toc_off = u16_at(&bytes, 0x28) as usize;
        let toc_len = u16_at(&bytes, 0x2A) as usize;
        let toc = BTNODE_TOC_BASE + toc_off;
        let key_base = toc + toc_len;
        let value_end = block_size
            - if flags & BTNODE_ROOT != 0 {
                BTREE_INFO_BYTES
            } else {
                0
            };
        if key_base > value_end || value_end > block_size {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "table of contents leaves no room for keys and values",
            });
        }
        let entry_bytes = if flags & BTNODE_FIXED_KV_SIZE != 0 {
            4
        } else {
            8
        };
        if nkeys * entry_bytes > toc_len {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "more keys than the table of contents holds",
            });
        }
        Ok(Self {
            paddr,
            bytes,
            flags,
            level,
            nkeys,
            key_base,
            value_end,
            toc,
        })
    }

    pub(crate) fn is_leaf(&self) -> bool {
        self.flags & BTNODE_LEAF != 0
    }

    pub(crate) fn entry(&self, index: usize) -> Result<(&[u8], &[u8]), VerifyError> {
        let fixed = self.flags & BTNODE_FIXED_KV_SIZE != 0;
        let malformed = |reason: &'static str| VerifyError::NodeMalformed {
            paddr: self.paddr,
            reason,
        };
        let (key_off, key_len, value_off, value_len) = if fixed {
            let at = self.toc + index * 4;
            let key_off = u16_at(&self.bytes, at) as usize;
            let value_off = u16_at(&self.bytes, at + 2) as usize;
            (key_off, None, value_off, None)
        } else {
            let at = self.toc + index * 8;
            (
                u16_at(&self.bytes, at) as usize,
                Some(u16_at(&self.bytes, at + 2) as usize),
                u16_at(&self.bytes, at + 4) as usize,
                Some(u16_at(&self.bytes, at + 6) as usize),
            )
        };
        let key_at = self
            .key_base
            .checked_add(key_off)
            .ok_or_else(|| malformed("key offset overflows"))?;
        if key_at >= self.value_end {
            return Err(malformed("key starts past the value area"));
        }
        let key_end = match key_len {
            Some(len) => key_at
                .checked_add(len)
                .filter(|end| *end <= self.value_end)
                .ok_or_else(|| malformed("key runs past the value area"))?,
            None => self.value_end,
        };
        let value_at = self
            .value_end
            .checked_sub(value_off)
            .filter(|at| *at >= self.key_base)
            .ok_or_else(|| malformed("value offset leaves the node"))?;
        let value_end = match value_len {
            Some(len) => value_at
                .checked_add(len)
                .filter(|end| *end <= self.value_end)
                .ok_or_else(|| malformed("value runs past the end of the node"))?,
            None => self.value_end,
        };
        Ok((
            &self.bytes[key_at..key_end],
            &self.bytes[value_at..value_end],
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OmapEntry {
    pub(crate) oid: u64,
    pub(crate) xid: u64,
    pub(crate) paddr: u64,
}

impl Verifier<'_> {
    pub(crate) fn read_omap(&mut self, paddr: u64, what: &'static str) -> Result<u64, VerifyError> {
        let omap = self.read_expecting(paddr, Some(paddr), TYPE_OMAP, what)?;
        if omap.storage() != OBJ_PHYSICAL {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "object map storage class",
                expected: OBJ_PHYSICAL as u64,
                observed: omap.storage() as u64,
            });
        }
        let tree_type = u32_at(&omap.bytes, 0x28);
        if tree_type & OBJ_TYPE_MASK != TYPE_BTREE {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "object map tree type",
                expected: TYPE_BTREE as u64,
                observed: (tree_type & OBJ_TYPE_MASK) as u64,
            });
        }
        Ok(u64_at(&omap.bytes, 0x30))
    }

    pub(crate) fn collect_omap(
        &mut self,
        root_paddr: u64,
        what: &'static str,
    ) -> Result<Vec<OmapEntry>, VerifyError> {
        let mut entries = Vec::new();
        let mut pending = vec![(root_paddr, true, None::<u16>)];
        let mut seen = std::collections::HashSet::new();
        while let Some((paddr, is_root, expected_level)) = pending.pop() {
            if !seen.insert(paddr) {
                return Err(VerifyError::NodeMalformed {
                    paddr,
                    reason: "object map tree node was reached more than once",
                });
            }
            let kind = if is_root { TYPE_BTREE } else { TYPE_BTREE_NODE };
            let object = self.read_expecting(paddr, None, kind, what)?;
            if object.subtype() & OBJ_TYPE_MASK != TYPE_OMAP {
                return Err(VerifyError::ObjectMismatch {
                    paddr,
                    field: "object map tree subtype",
                    expected: TYPE_OMAP as u64,
                    observed: (object.subtype() & OBJ_TYPE_MASK) as u64,
                });
            }
            let node = BTreeNode::decode(&object, self.block_size)?;
            if let Some(level) = expected_level
                && node.level != level
            {
                return Err(VerifyError::NodeMalformed {
                    paddr,
                    reason: "object map tree node is not one level below its parent",
                });
            }
            let mut previous: Option<(u64, u64)> = None;
            for index in 0..node.nkeys {
                let (key, value) = node.entry(index)?;
                if key.len() < 16 {
                    return Err(VerifyError::NodeMalformed {
                        paddr,
                        reason: "object map key is shorter than 16 bytes",
                    });
                }
                let oid = u64_at(key, 0);
                let xid = u64_at(key, 8);
                if let Some(earlier) = previous
                    && (oid, xid) <= earlier
                {
                    return Err(VerifyError::RecordsOutOfOrder { paddr, index });
                }
                previous = Some((oid, xid));
                if node.is_leaf() {
                    if value.len() < 16 {
                        return Err(VerifyError::NodeMalformed {
                            paddr,
                            reason: "object map value is shorter than 16 bytes",
                        });
                    }
                    entries.push(OmapEntry {
                        oid,
                        xid,
                        paddr: u64_at(value, 8),
                    });
                } else {
                    if value.len() < 8 {
                        return Err(VerifyError::NodeMalformed {
                            paddr,
                            reason: "object map index value is shorter than 8 bytes",
                        });
                    }
                    let child_level =
                        node.level
                            .checked_sub(1)
                            .ok_or(VerifyError::NodeMalformed {
                                paddr,
                                reason: "an index node claims to be at the leaf level",
                            })?;
                    pending.push((u64_at(value, 0), false, Some(child_level)));
                }
            }
            if node.level == 0 && !node.is_leaf() {
                return Err(VerifyError::NodeMalformed {
                    paddr,
                    reason: "level zero node is not marked a leaf",
                });
            }
        }
        Ok(entries)
    }
}

// Newest entry no later than `xid`, which is what nx_mount does.
pub(crate) fn resolve(entries: &[OmapEntry], oid: u64, xid: u64) -> Result<u64, VerifyError> {
    entries
        .iter()
        .filter(|entry| entry.oid == oid && entry.xid <= xid)
        .max_by_key(|entry| entry.xid)
        .map(|entry| entry.paddr)
        .ok_or(VerifyError::UnmappedVirtualOid { oid })
}

fn validate_container_header(object: &Object) -> Result<(), VerifyError> {
    let expected = OBJ_EPHEMERAL | TYPE_NX_SUPERBLOCK;
    if object.o_type() != expected {
        return Err(VerifyError::ObjectMismatch {
            paddr: object.paddr,
            field: "container superblock object type",
            expected: expected as u64,
            observed: object.o_type() as u64,
        });
    }
    Ok(())
}

fn validate_checkpoint_bounds(object: &Object) -> Result<(), VerifyError> {
    let bytes = &object.bytes;
    for (count_at, next_at, index_at, len_at, ring, segment, cursor) in [
        (
            0x68,
            0x80,
            0x88,
            0x8C,
            "checkpoint descriptor ring size",
            "checkpoint descriptor segment length",
            "checkpoint descriptor ring cursor",
        ),
        (
            0x6C,
            0x84,
            0x90,
            0x94,
            "checkpoint data ring size",
            "checkpoint data segment length",
            "checkpoint data ring cursor",
        ),
    ] {
        let count = u32_at(bytes, count_at) & 0x7FFF_FFFF;
        if count < NX_MIN_CHECKPOINT_RING_BLOCKS {
            return Err(VerifyError::FieldOutOfRange {
                what: ring,
                observed: count as u64,
            });
        }
        let index = u32_at(bytes, index_at);
        if index >= count {
            return Err(VerifyError::FieldOutOfRange {
                what: "checkpoint area index",
                observed: index as u64,
            });
        }
        let length = u32_at(bytes, len_at);
        if length < NX_MIN_CHECKPOINT_SEGMENT_BLOCKS || length > count {
            return Err(VerifyError::FieldOutOfRange {
                what: segment,
                observed: length as u64,
            });
        }
        let next = u32_at(bytes, next_at);
        if next >= count {
            return Err(VerifyError::FieldOutOfRange {
                what: cursor,
                observed: next as u64,
            });
        }
    }
    Ok(())
}

fn expected_max_file_systems(block_count: u64, block_size: u32) -> u64 {
    let bytes = block_count.saturating_mul(block_size as u64);
    const HALF_GIB: u64 = 512 * 1024 * 1024;
    bytes.div_ceil(HALF_GIB).clamp(1, 100)
}

fn validate_ephemeral_info(sb: &[u8]) -> Result<(), VerifyError> {
    let word0 = u64_at(sb, NX_EPHEMERAL_INFO_OFFSET);
    let version = word0 & 0xF;
    if version != NX_EPH_INFO_VERSION {
        return Err(VerifyError::FieldMismatch {
            what: "nx_ephemeral_info[0] version",
            expected: NX_EPH_INFO_VERSION,
            observed: version,
        });
    }
    let structs_per_fs = (word0 >> 16) & 0xFFFF;
    if structs_per_fs != NX_EPH_INFO_STRUCTS_PER_FS {
        return Err(VerifyError::FieldMismatch {
            what: "nx_ephemeral_info[0] structures per fs",
            expected: NX_EPH_INFO_STRUCTS_PER_FS,
            observed: structs_per_fs,
        });
    }
    let min_block_count = word0 >> 32;
    if !NX_EPH_INFO_MIN_BLOCK_COUNTS.contains(&min_block_count) {
        return Err(VerifyError::FieldOutOfRange {
            what: "nx_ephemeral_info[0] minimum block count per structure",
            observed: min_block_count,
        });
    }
    for index in 1..4 {
        let word = u64_at(sb, NX_EPHEMERAL_INFO_OFFSET + index * 8);
        if word != 0 {
            return Err(VerifyError::FieldOutOfRange {
                what: "nx_ephemeral_info[1..4], reserved and must be zero",
                observed: word,
            });
        }
    }
    Ok(())
}

fn validate_fusion_and_keylocker_fields(
    zero: &[u8],
    sb: &[u8],
    block_count: u64,
) -> Result<(), VerifyError> {
    if zero[NX_FUSION_UUID_OFFSET..NX_FUSION_UUID_OFFSET + 16]
        != sb[NX_FUSION_UUID_OFFSET..NX_FUSION_UUID_OFFSET + 16]
    {
        return Err(VerifyError::FieldMismatch {
            what: "nx_fusion_uuid",
            expected: u64_at(zero, NX_FUSION_UUID_OFFSET),
            observed: u64_at(sb, NX_FUSION_UUID_OFFSET),
        });
    }
    let is_fusion = sb[NX_FUSION_UUID_OFFSET..NX_FUSION_UUID_OFFSET + 16] != [0u8; 16];
    if !is_fusion {
        for (at, name) in [
            (NX_FUSION_MT_OID_OFFSET, "nx_fusion_mt_oid"),
            (NX_FUSION_WBC_OID_OFFSET, "nx_fusion_wbc_oid"),
            (NX_FUSION_WBC_OFFSET, "nx_fusion_wbc paddr"),
            (NX_FUSION_WBC_OFFSET + 8, "nx_fusion_wbc block count"),
        ] {
            let value = u64_at(sb, at);
            if value != 0 {
                return Err(VerifyError::FieldOutOfRange {
                    what: name,
                    observed: value,
                });
            }
        }
    }

    let jumpstart = u64_at(sb, NX_EFI_JUMPSTART_OFFSET);
    if jumpstart != 0 {
        region_within("EFI jumpstart record", jumpstart, 1, block_count)?;
    }
    let keylocker_paddr = u64_at(sb, NX_KEYLOCKER_OFFSET);
    let keylocker_count = u64_at(sb, NX_KEYLOCKER_OFFSET + 8);
    if keylocker_count != 0 {
        region_within("keybag", keylocker_paddr, keylocker_count, block_count)?;
    } else if keylocker_paddr != 0 {
        return Err(VerifyError::FieldOutOfRange {
            what: "nx_keylocker paddr with no block count",
            observed: keylocker_paddr,
        });
    }
    Ok(())
}

pub fn verify_container(source: &mut dyn BlockSource) -> Result<VerifiedContainer, VerifyError> {
    let mut probe = vec![0u8; 4096];
    source.read_block(0, &mut probe)?;
    let magic = u32_at(&probe, 0x20);
    if magic != NX_MAGIC {
        return Err(VerifyError::BadMagic {
            paddr: 0,
            observed: magic,
        });
    }
    let block_size = u32_at(&probe, 0x24);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(VerifyError::UnsupportedBlockSize { block_size });
    }
    let block_count = u64_at(&probe, 0x28);
    if block_count == 0 || block_count > MAX_REASONABLE_BLOCKS {
        return Err(VerifyError::ImplausibleBlockCount { block_count });
    }

    let mut verifier = Verifier {
        source,
        block_size: block_size as usize,
        block_count,
        objects_checked: 0,
        in_use: Vec::new(),
    };

    let zero = verifier.read_checked(0)?;
    validate_container_header(&zero)?;
    verifier.note(0, "container superblock copy");
    let descriptor_base = u64_at(&zero.bytes, 0x70);
    let descriptor_blocks = u32_at(&zero.bytes, 0x68) as u64;
    if descriptor_blocks == 0 {
        return Err(VerifyError::FieldOutOfRange {
            what: "checkpoint descriptor block count",
            observed: 0,
        });
    }
    region_within(
        "checkpoint descriptor",
        descriptor_base,
        descriptor_blocks,
        block_count,
    )?;

    let mut best: Option<(u64, u64)> = None;
    for slot in 0..descriptor_blocks {
        let paddr = descriptor_base + slot;
        let mut bytes = vec![0u8; block_size as usize];
        verifier.source.read_block(paddr, &mut bytes)?;
        if !checksum_valid(&bytes) {
            continue;
        }
        let o_type = u32_at(&bytes, 0x18);
        if o_type & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
            continue;
        }
        if u32_at(&bytes, 0x20) != NX_MAGIC {
            continue;
        }
        let xid = u64_at(&bytes, 0x10);
        if best.is_none_or(|(best_xid, _)| xid > best_xid) {
            best = Some((xid, paddr));
        }
    }
    let (xid, superblock_paddr) = best.ok_or(VerifyError::NoCheckpoint)?;
    let superblock = verifier.read_checked(superblock_paddr)?;
    validate_container_header(&superblock)?;
    validate_checkpoint_bounds(&superblock)?;
    verifier.note(superblock_paddr, "container superblock");

    let sb = superblock.bytes.clone();
    if u64_at(&sb, 0x28) != block_count || u32_at(&sb, 0x24) != block_size {
        return Err(VerifyError::ObjectMismatch {
            paddr: superblock_paddr,
            field: "container geometry",
            expected: block_count,
            observed: u64_at(&sb, 0x28),
        });
    }

    let data_base = u64_at(&sb, 0x78);
    let data_blocks = u32_at(&sb, 0x6C) as u64;
    region_within("checkpoint data", data_base, data_blocks, block_count)?;
    let descriptor_index = u32_at(&sb, 0x88) as u64;
    let descriptor_len = u32_at(&sb, 0x8C) as u64;
    if descriptor_len == 0 || descriptor_len > descriptor_blocks {
        return Err(VerifyError::FieldOutOfRange {
            what: "checkpoint descriptor length",
            observed: descriptor_len,
        });
    }

    for (at, from_zero, name) in [
        (0x68u64, descriptor_blocks, "nx_xp_desc_blocks"),
        (0x70, descriptor_base, "nx_xp_desc_base"),
        (0x6C, data_blocks, "nx_xp_data_blocks"),
        (0x78, data_base, "nx_xp_data_base"),
    ] {
        let from_checkpoint = if at == 0x68 || at == 0x6C {
            u32_at(&sb, at as usize) as u64
        } else {
            u64_at(&sb, at as usize)
        };
        if from_checkpoint != from_zero {
            return Err(VerifyError::FieldMismatch {
                what: name,
                expected: from_zero,
                observed: from_checkpoint,
            });
        }
    }

    let superblock_slot = superblock_paddr - descriptor_base;
    let expected_index =
        (superblock_slot + descriptor_blocks - descriptor_len + 1) % descriptor_blocks;
    if expected_index != descriptor_index {
        return Err(VerifyError::FieldMismatch {
            what: "nx_xp_desc_index",
            expected: expected_index,
            observed: descriptor_index,
        });
    }

    validate_ephemeral_info(&sb)?;

    let mut ephemeral: Vec<(u64, u64, u32)> = Vec::new();
    let mut ephemeral_blocks: Vec<(u64, u64)> = Vec::new();
    for slot in 0..descriptor_len {
        let paddr = descriptor_base + (descriptor_index + slot) % descriptor_blocks;
        let object = verifier.read_checked(paddr)?;
        if object.kind() != TYPE_CHECKPOINT_MAP {
            continue;
        }
        if object.storage() != OBJ_PHYSICAL {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "checkpoint map storage class",
                expected: OBJ_PHYSICAL as u64,
                observed: object.storage() as u64,
            });
        }
        if object.oid() != paddr {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "checkpoint map object id",
                expected: paddr,
                observed: object.oid(),
            });
        }
        verifier.note(paddr, "checkpoint map");
        if object.xid() != xid {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "checkpoint map transaction id",
                expected: xid,
                observed: object.xid(),
            });
        }
        let count = u32_at(&object.bytes, 0x24) as usize;
        let capacity = (block_size as usize - 0x28) / CHECKPOINT_MAPPING_BYTES;
        if count > capacity {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "checkpoint map claims more mappings than it can hold",
            });
        }
        for index in 0..count {
            let at = 0x28 + index * CHECKPOINT_MAPPING_BYTES;
            let o_type = u32_at(&object.bytes, at);
            let subtype = u32_at(&object.bytes, at + 4);
            let size = u32_at(&object.bytes, at + 8);
            let oid = u64_at(&object.bytes, at + 24);
            let mapped = u64_at(&object.bytes, at + 32);
            if o_type & OBJ_STORAGE_MASK != OBJ_EPHEMERAL {
                return Err(VerifyError::FieldOutOfRange {
                    what: "checkpoint mapping storage class",
                    observed: (o_type & OBJ_STORAGE_MASK) as u64,
                });
            }
            if subtype & OBJ_STORAGE_MASK != 0 {
                return Err(VerifyError::FieldOutOfRange {
                    what: "checkpoint mapping subtype storage bits",
                    observed: (subtype & OBJ_STORAGE_MASK) as u64,
                });
            }
            if size == 0 || !(size as u64).is_multiple_of(block_size as u64) {
                return Err(VerifyError::FieldOutOfRange {
                    what: "checkpoint mapping size",
                    observed: size as u64,
                });
            }
            let mapped_blocks = size as u64 / block_size as u64;
            if mapped < data_base
                || mapped_blocks > data_blocks
                || mapped - data_base > data_blocks - mapped_blocks
            {
                return Err(VerifyError::MappingOutsideDataArea { oid, paddr: mapped });
            }
            let target = verifier.read_checked_sized(mapped, mapped_blocks as usize)?;
            if target.oid() != oid || target.o_type() != o_type || target.subtype() != subtype {
                return Err(VerifyError::ObjectMismatch {
                    paddr: mapped,
                    field: "checkpoint mapping",
                    expected: oid,
                    observed: target.oid(),
                });
            }
            if target.storage() != OBJ_EPHEMERAL {
                return Err(VerifyError::ObjectMismatch {
                    paddr: mapped,
                    field: "ephemeral storage class",
                    expected: OBJ_EPHEMERAL as u64,
                    observed: target.storage() as u64,
                });
            }
            for offset in 0..mapped_blocks {
                verifier.note(mapped + offset, "ephemeral object");
            }
            ephemeral.push((oid, mapped, o_type));
            ephemeral_blocks.push((oid, mapped_blocks));
        }
    }

    let find = |oid: u64| -> Result<u64, VerifyError> {
        ephemeral
            .iter()
            .find(|(mapped_oid, _, _)| *mapped_oid == oid)
            .map(|(_, paddr, _)| *paddr)
            .ok_or(VerifyError::UnmappedEphemeralOid { oid })
    };
    let find_blocks = |oid: u64| -> Result<usize, VerifyError> {
        ephemeral_blocks
            .iter()
            .find(|(mapped_oid, _)| *mapped_oid == oid)
            .map(|(_, blocks)| *blocks as usize)
            .ok_or(VerifyError::UnmappedEphemeralOid { oid })
    };

    let reaper_paddr = find(u64_at(&sb, 0xA8))?;
    let reaper = verifier.read_expecting(reaper_paddr, None, TYPE_NX_REAPER, "reaper")?;
    let reap_list_head = u64_at(&reaper.bytes, 0x30);
    let reap_list_tail = u64_at(&reaper.bytes, 0x38);
    let reap_list_count = u32_at(&reaper.bytes, 0x44);
    let holds_a_list = reap_list_count != 0;
    if (reap_list_head != 0) != holds_a_list || (reap_list_tail != 0) != holds_a_list {
        return Err(VerifyError::ReapListBroken {
            reason: "the reaper's list count and its head and tail disagree about whether a list exists",
        });
    }
    if holds_a_list {
        if reap_list_tail != reap_list_head {
            return Err(VerifyError::ReapListBroken {
                reason: "the reaper's head and tail name different lists",
            });
        }
        let reap_list_paddr = find(reap_list_head)?;
        let reap_list = verifier.read_expecting(
            reap_list_paddr,
            Some(reap_list_head),
            TYPE_NX_REAP_LIST,
            "reap list",
        )?;
        verify_reap_list(&reap_list.bytes, block_size as usize)?;
    }

    let spaceman_oid = u64_at(&sb, 0x98);
    let spaceman_paddr = find(spaceman_oid)?;
    let spaceman_blocks = find_blocks(spaceman_oid)?;
    let spaceman = verifier.read_expecting_sized(
        spaceman_paddr,
        spaceman_blocks,
        None,
        TYPE_SPACEMAN,
        "space manager",
    )?;
    let allocation = verifier.verify_spaceman(&spaceman.bytes, xid)?;

    for oid in &allocation.free_queue_tree_oids {
        let queue_paddr = find(*oid)?;
        let tree =
            verifier.read_expecting(queue_paddr, Some(*oid), TYPE_BTREE, "free queue tree")?;
        if tree.storage() != OBJ_EPHEMERAL {
            return Err(VerifyError::ObjectMismatch {
                paddr: queue_paddr,
                field: "free queue storage class",
                expected: OBJ_EPHEMERAL as u64,
                observed: tree.storage() as u64,
            });
        }
    }

    let container_omap_paddr = u64_at(&sb, 0xA0);
    let omap_tree = verifier.read_omap(container_omap_paddr, "container object map")?;
    let omap_entries = verifier.collect_omap(omap_tree, "container object map tree")?;

    let max_file_systems = u32_at(&sb, 0xB4);
    let expected_max_file_systems = expected_max_file_systems(block_count, block_size);
    if max_file_systems as u64 != expected_max_file_systems {
        return Err(VerifyError::FieldMismatch {
            what: "nx_max_file_systems",
            expected: expected_max_file_systems,
            observed: max_file_systems as u64,
        });
    }
    let mut volumes = Vec::new();
    for index in 0..max_file_systems as usize {
        let oid = u64_at(&sb, 0xB8 + index * 8);
        if oid == 0 {
            continue;
        }
        let paddr = resolve(&omap_entries, oid, xid)?;
        let volume = verifier.verify_volume(oid, paddr, xid)?;
        volumes.push(volume);
    }

    validate_fusion_and_keylocker_fields(&zero.bytes, &sb, block_count)?;

    let in_use = std::mem::take(&mut verifier.in_use);
    for (paddr, what) in &in_use {
        if !allocation.is_allocated(*paddr) {
            return Err(VerifyError::BlockNotAllocated {
                paddr: *paddr,
                what,
            });
        }
    }
    let mut blocks_in_use: Vec<u64> = in_use.iter().map(|(paddr, _)| *paddr).collect();
    blocks_in_use.sort_unstable();
    blocks_in_use.dedup();

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[0x48..0x58]);

    Ok(VerifiedContainer {
        block_size,
        block_count,
        uuid,
        xid,
        superblock_paddr,
        max_file_systems,
        free_block_count: allocation.free_block_count,
        ephemeral,
        volumes,
        objects_checked: verifier.objects_checked,
        blocks_in_use,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSealReport {
    pub oid: u64,
    pub paddr: u64,
    pub fs_index: u32,
    pub name: String,
    pub role: u16,
    pub uuid: [u8; 16],
    pub sealed: bool,
    pub incompatible_features: u64,
    pub integrity_meta_oid: u64,
    pub seal: Option<VolumeSeal>,
    pub snapshots: VolumeSnapshots,
    pub root_to_xid: u64,
    pub volume_group_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRecord {
    pub xid: u64,
    pub name: String,
    pub flags: u32,
    pub sblock_oid: u64,
    pub extentref_tree_oid: u64,
    pub create_time: u64,
    pub change_time: u64,
    pub inum: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeSnapshots {
    pub tree_paddr: u64,
    pub declared_count: u64,
    pub snapshots: Vec<SnapshotRecord>,
    pub names: Vec<(String, u64)>,
}

impl VolumeSnapshots {
    pub fn xid_for_name(&self, name: &str) -> Option<u64> {
        self.names
            .iter()
            .find(|(recorded, _)| recorded == name)
            .map(|(_, xid)| *xid)
    }

    // The kernel looks the root snapshot up by name at root mount, so the name index is the authority, not any seal.
    pub fn root_snapshot_name(&self) -> Option<&str> {
        self.names
            .iter()
            .filter(|(name, _)| name.starts_with(ROOT_SNAPSHOT_PREFIX))
            .fold(None::<(&str, u64)>, |best, (name, xid)| match best {
                Some((_, best_xid)) if best_xid >= *xid => best,
                _ => Some((name.as_str(), *xid)),
            })
            .map(|(name, _)| name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSeals {
    pub block_size: u32,
    pub block_count: u64,
    pub uuid: [u8; 16],
    pub xid: u64,
    pub superblock_paddr: u64,
    pub volumes: Vec<VolumeSealReport>,
}

pub fn read_container_seals(source: &mut dyn BlockSource) -> Result<ContainerSeals, VerifyError> {
    let mut probe = vec![0u8; 4096];
    source.read_block(0, &mut probe)?;
    let magic = u32_at(&probe, 0x20);
    if magic != NX_MAGIC {
        return Err(VerifyError::BadMagic {
            paddr: 0,
            observed: magic,
        });
    }
    let block_size = u32_at(&probe, 0x24);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(VerifyError::UnsupportedBlockSize { block_size });
    }
    let block_count = u64_at(&probe, 0x28);
    if block_count == 0 || block_count > MAX_REASONABLE_BLOCKS {
        return Err(VerifyError::ImplausibleBlockCount { block_count });
    }

    let mut verifier = Verifier {
        source,
        block_size: block_size as usize,
        block_count,
        objects_checked: 0,
        in_use: Vec::new(),
    };

    let zero = verifier.read_checked(0)?;
    let descriptor_base = u64_at(&zero.bytes, 0x70);
    let descriptor_blocks = u32_at(&zero.bytes, 0x68) as u64;
    if descriptor_blocks == 0 {
        return Err(VerifyError::FieldOutOfRange {
            what: "checkpoint descriptor block count",
            observed: 0,
        });
    }
    region_within(
        "checkpoint descriptor",
        descriptor_base,
        descriptor_blocks,
        block_count,
    )?;

    let mut best: Option<(u64, u64)> = None;
    for slot in 0..descriptor_blocks {
        let paddr = descriptor_base + slot;
        let mut bytes = vec![0u8; block_size as usize];
        verifier.source.read_block(paddr, &mut bytes)?;
        if !checksum_valid(&bytes) {
            continue;
        }
        let o_type = u32_at(&bytes, 0x18);
        if o_type & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
            continue;
        }
        if u32_at(&bytes, 0x20) != NX_MAGIC {
            continue;
        }
        let xid = u64_at(&bytes, 0x10);
        if best.is_none_or(|(best_xid, _)| xid > best_xid) {
            best = Some((xid, paddr));
        }
    }
    let (xid, superblock_paddr) = best.ok_or(VerifyError::NoCheckpoint)?;
    let superblock = verifier.read_checked(superblock_paddr)?;
    validate_container_header(&superblock)?;
    validate_checkpoint_bounds(&superblock)?;
    let sb = superblock.bytes.clone();
    if u64_at(&sb, 0x28) != block_count || u32_at(&sb, 0x24) != block_size {
        return Err(VerifyError::ObjectMismatch {
            paddr: superblock_paddr,
            field: "container geometry",
            expected: block_count,
            observed: u64_at(&sb, 0x28),
        });
    }
    validate_ephemeral_info(&sb)?;

    let container_omap_paddr = u64_at(&sb, 0xA0);
    let omap_tree = verifier.read_omap(container_omap_paddr, "container object map")?;
    let omap_entries = verifier.collect_omap(omap_tree, "container object map tree")?;

    let max_file_systems = u32_at(&sb, 0xB4);
    let expected_max_file_systems = expected_max_file_systems(block_count, block_size);
    if max_file_systems as u64 != expected_max_file_systems {
        return Err(VerifyError::FieldMismatch {
            what: "nx_max_file_systems",
            expected: expected_max_file_systems,
            observed: max_file_systems as u64,
        });
    }

    let mut volumes = Vec::new();
    for index in 0..max_file_systems as usize {
        let oid = u64_at(&sb, 0xB8 + index * 8);
        if oid == 0 {
            continue;
        }
        let paddr = resolve(&omap_entries, oid, xid)?;
        volumes.push(verifier.read_volume_seal_report(oid, paddr, xid)?);
    }

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[0x48..0x58]);

    Ok(ContainerSeals {
        block_size,
        block_count,
        uuid,
        xid,
        superblock_paddr,
        volumes,
    })
}

impl Verifier<'_> {
    fn read_volume_seal_report(
        &mut self,
        oid: u64,
        paddr: u64,
        xid: u64,
    ) -> Result<VolumeSealReport, VerifyError> {
        let volume = self.read_expecting(paddr, Some(oid), TYPE_FS, "volume superblock")?;
        if volume.storage() != OBJ_VIRTUAL {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "volume storage class",
                expected: OBJ_VIRTUAL as u64,
                observed: volume.storage() as u64,
            });
        }
        let bytes = volume.bytes.clone();
        let magic = u32_at(&bytes, 0x20);
        if magic != APFS_MAGIC {
            return Err(VerifyError::BadMagic {
                paddr,
                observed: magic,
            });
        }

        let incompatible_features = u64_at(&bytes, 0x38);
        let integrity_meta_oid = u64_at(&bytes, APSB_INTEGRITY_META_OID_OFFSET);
        let seal = if integrity_meta_oid == 0 {
            None
        } else {
            let volume_omap_paddr = u64_at(&bytes, 0x80);
            let omap_tree = self.read_omap(volume_omap_paddr, "volume object map")?;
            let entries = self.collect_omap(omap_tree, "volume object map tree")?;
            let meta_paddr = resolve(&entries, integrity_meta_oid, xid)?;
            Some(self.read_volume_seal(oid, integrity_meta_oid, meta_paddr)?)
        };

        let name_end = bytes[0x2C0..0x3C0]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        let name = String::from_utf8_lossy(&bytes[0x2C0..0x2C0 + name_end]).into_owned();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[0xF0..0x100]);

        let snap_meta_tree_paddr = u64_at(&bytes, APSB_SNAP_META_TREE_OID_OFFSET);
        let declared_count = u64_at(&bytes, APSB_NUM_SNAPSHOTS_OFFSET);
        let snapshots = self.read_volume_snapshots(snap_meta_tree_paddr, declared_count)?;
        let root_to_xid = u64_at(&bytes, APSB_ROOT_TO_XID_OFFSET);
        let mut volume_group_id = [0u8; 16];
        volume_group_id
            .copy_from_slice(&bytes[APSB_VOLUME_GROUP_OFFSET..APSB_VOLUME_GROUP_OFFSET + 16]);

        Ok(VolumeSealReport {
            oid,
            paddr,
            fs_index: u32_at(&bytes, 0x24),
            name,
            role: u16_at(&bytes, 0x3C4),
            uuid,
            sealed: incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0,
            incompatible_features,
            integrity_meta_oid,
            seal,
            snapshots,
            root_to_xid,
            volume_group_id,
        })
    }

    pub(crate) fn read_volume_snapshots(
        &mut self,
        tree_paddr: u64,
        declared_count: u64,
    ) -> Result<VolumeSnapshots, VerifyError> {
        let mut found = VolumeSnapshots {
            tree_paddr,
            declared_count,
            snapshots: Vec::new(),
            names: Vec::new(),
        };
        if tree_paddr == 0 {
            return Ok(found);
        }
        let root = self.read_expecting(
            tree_paddr,
            Some(tree_paddr),
            TYPE_BTREE,
            "snapshot metadata tree",
        )?;
        if root.storage() != OBJ_PHYSICAL {
            return Err(VerifyError::ObjectMismatch {
                paddr: tree_paddr,
                field: "snapshot metadata tree storage class",
                expected: OBJ_PHYSICAL as u64,
                observed: root.storage() as u64,
            });
        }

        let root_node = BTreeNode::decode(&root, self.block_size)?;
        let mut level = root_node.level;
        let mut frontier = Vec::new();
        take_snapshot_records(&root_node, &mut found, &mut frontier)?;
        while !frontier.is_empty() {
            level = level.checked_sub(1).ok_or(VerifyError::NodeMalformed {
                paddr: tree_paddr,
                reason: "snapshot metadata tree descends below its leaves",
            })?;
            let mut next = Vec::new();
            for paddr in frontier {
                let object = self.read_expecting(
                    paddr,
                    Some(paddr),
                    TYPE_BTREE_NODE,
                    "snapshot metadata tree node",
                )?;
                let node = BTreeNode::decode(&object, self.block_size)?;
                if node.level != level {
                    return Err(VerifyError::NodeMalformed {
                        paddr,
                        reason: "snapshot metadata node is not one level below its parent",
                    });
                }
                take_snapshot_records(&node, &mut found, &mut next)?;
            }
            frontier = next;
        }
        Ok(found)
    }
}

fn take_snapshot_records(
    node: &BTreeNode,
    found: &mut VolumeSnapshots,
    children: &mut Vec<u64>,
) -> Result<(), VerifyError> {
    for index in 0..node.nkeys {
        let (key, value) = node.entry(index)?;
        if key.len() < 8 {
            return Err(VerifyError::NodeMalformed {
                paddr: node.paddr,
                reason: "snapshot record key is shorter than its header",
            });
        }
        if !node.is_leaf() {
            if value.len() < 8 {
                return Err(VerifyError::NodeMalformed {
                    paddr: node.paddr,
                    reason: "snapshot metadata index record has no child block",
                });
            }
            children.push(u64_at(value, 0));
            continue;
        }
        let header = u64_at(key, 0);
        let kind = header >> 60;
        let obj_id = header & 0x0FFF_FFFF_FFFF_FFFF;
        match kind {
            J_SNAP_METADATA => {
                if value.len() < 0x32 {
                    return Err(VerifyError::NodeMalformed {
                        paddr: node.paddr,
                        reason: "snapshot metadata value is truncated",
                    });
                }
                let name_len = u16_at(value, 0x30) as usize;
                if name_len == 0 || 0x32 + name_len > value.len() {
                    return Err(VerifyError::NodeMalformed {
                        paddr: node.paddr,
                        reason: "snapshot metadata name length leaves the value",
                    });
                }
                found.snapshots.push(SnapshotRecord {
                    xid: obj_id,
                    name: String::from_utf8_lossy(&value[0x32..0x32 + name_len - 1]).into_owned(),
                    flags: u32_at(value, 0x2C),
                    sblock_oid: u64_at(value, 0x08),
                    extentref_tree_oid: u64_at(value, 0x00),
                    create_time: u64_at(value, 0x10),
                    change_time: u64_at(value, 0x18),
                    inum: u64_at(value, 0x20),
                });
            }
            J_SNAP_NAME => {
                if key.len() < 10 {
                    return Err(VerifyError::NodeMalformed {
                        paddr: node.paddr,
                        reason: "snapshot name key is shorter than its name length",
                    });
                }
                let name_len = u16_at(key, 8) as usize;
                if name_len == 0 || 10 + name_len > key.len() {
                    return Err(VerifyError::NodeMalformed {
                        paddr: node.paddr,
                        reason: "snapshot name length leaves the key",
                    });
                }
                if value.len() < 8 {
                    return Err(VerifyError::NodeMalformed {
                        paddr: node.paddr,
                        reason: "snapshot name record has no transaction id",
                    });
                }
                found.names.push((
                    String::from_utf8_lossy(&key[10..10 + name_len - 1]).into_owned(),
                    u64_at(value, 0),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn region_within(
    what: &'static str,
    first: u64,
    count: u64,
    block_count: u64,
) -> Result<(), VerifyError> {
    let end = first
        .checked_add(count)
        .ok_or(VerifyError::RegionOutOfBounds { what, first, count })?;
    if end > block_count {
        return Err(VerifyError::RegionOutOfBounds { what, first, count });
    }
    Ok(())
}

struct Allocation {
    blocks_per_chunk: u64,
    bitmaps: Vec<Option<Vec<u8>>>,
    free_block_count: u64,
    free_queue_tree_oids: Vec<u64>,
}

impl Allocation {
    fn is_allocated(&self, paddr: u64) -> bool {
        let chunk = (paddr / self.blocks_per_chunk) as usize;
        let bit = (paddr % self.blocks_per_chunk) as usize;
        match self.bitmaps.get(chunk) {
            Some(Some(bitmap)) => bitmap[bit >> 3] >> (bit & 7) & 1 == 1,
            Some(None) => false,
            None => false,
        }
    }
}

impl Verifier<'_> {
    fn verify_spaceman(&mut self, sm: &[u8], xid: u64) -> Result<Allocation, VerifyError> {
        let block_size = self.block_size as u64;
        if u32_at(sm, 0x20) as u64 != block_size {
            return Err(VerifyError::FieldOutOfRange {
                what: "space manager block size",
                observed: u32_at(sm, 0x20) as u64,
            });
        }
        let blocks_per_chunk = u32_at(sm, 0x24) as u64;
        if blocks_per_chunk != block_size * 8 {
            return Err(VerifyError::FieldOutOfRange {
                what: "blocks per chunk",
                observed: blocks_per_chunk,
            });
        }
        let chunks_per_cib = u32_at(sm, 0x28) as u64;
        if chunks_per_cib == 0 || chunks_per_cib > (block_size - 0x28) / CHUNK_INFO_BYTES as u64 {
            return Err(VerifyError::FieldOutOfRange {
                what: "chunks per chunk info block",
                observed: chunks_per_cib,
            });
        }
        if u32_at(sm, 0x154) != SPACEMAN_STRUCT_SIZE {
            return Err(VerifyError::FieldOutOfRange {
                what: "space manager struct size",
                observed: u32_at(sm, 0x154) as u64,
            });
        }

        let device_block_count = u64_at(sm, 0x30);
        if device_block_count != self.block_count {
            return Err(VerifyError::FieldOutOfRange {
                what: "space manager device block count",
                observed: device_block_count,
            });
        }
        let chunk_count = u64_at(sm, 0x38);
        let cib_count = u32_at(sm, 0x40) as usize;
        let cab_count = u32_at(sm, 0x44) as usize;
        let cibs_per_cab = u32_at(sm, 0x2C) as usize;
        let recorded_free = u64_at(sm, 0x48);
        let cib_addr_offset = u32_at(sm, 0x50) as usize;
        let direct_entries = if cab_count == 0 { cib_count } else { cab_count };
        if cib_addr_offset + direct_entries * 8 > sm.len() {
            return Err(VerifyError::FieldOutOfRange {
                what: "chunk info address array offset",
                observed: cib_addr_offset as u64,
            });
        }

        let ip_block_count = u64_at(sm, 0x98);
        let ip_bm_size_in_blocks = u32_at(sm, 0xA0) as u64;
        let ip_bm_block_count = u32_at(sm, 0xA4) as u64;
        let ip_bm_base = u64_at(sm, 0xA8);
        let ip_base = u64_at(sm, 0xB0);
        region_within("internal pool", ip_base, ip_block_count, self.block_count)?;
        region_within(
            "internal pool bitmap ring",
            ip_bm_base,
            ip_bm_block_count,
            self.block_count,
        )?;
        let ip_bm_free_next_offset =
            verify_ip_ring(sm, ip_bm_size_in_blocks, ip_bm_block_count, xid)?;
        // sm_dev[SD_MAIN].addr_offset is packed immediately after the ip ring's free-chain array, 8-byte aligned.
        let expected_cib_addr_offset =
            align8(ip_bm_free_next_offset + ip_bm_block_count as u32 * 2);
        if cib_addr_offset as u32 != expected_cib_addr_offset {
            return Err(VerifyError::FieldMismatch {
                what: "sm_dev[SD_MAIN].addr_offset",
                expected: expected_cib_addr_offset as u64,
                observed: cib_addr_offset as u64,
            });
        }
        let in_internal_pool = |paddr: u64| paddr >= ip_base && paddr - ip_base < ip_block_count;

        let cib_addrs: Vec<u64> = if cab_count == 0 {
            (0..cib_count)
                .map(|index| u64_at(sm, cib_addr_offset + index * 8))
                .collect()
        } else {
            if cibs_per_cab == 0 {
                return Err(VerifyError::FieldOutOfRange {
                    what: "chunk-info blocks per address block",
                    observed: 0,
                });
            }
            let expected_cab_count = cib_count.div_ceil(cibs_per_cab);
            if cab_count != expected_cab_count {
                return Err(VerifyError::FieldMismatch {
                    what: "space manager chunk-info address block count",
                    expected: expected_cab_count as u64,
                    observed: cab_count as u64,
                });
            }
            let mut addrs = Vec::with_capacity(cib_count);
            for cab_index in 0..cab_count {
                let cab_paddr = u64_at(sm, cib_addr_offset + cab_index * 8);
                if !in_internal_pool(cab_paddr) {
                    return Err(VerifyError::AddressOutsideInternalPool {
                        paddr: cab_paddr,
                        what: "chunk-info address block",
                    });
                }
                let cab = self.read_expecting(
                    cab_paddr,
                    Some(cab_paddr),
                    TYPE_SPACEMAN_CAB,
                    "chunk-info address block",
                )?;
                if cab.storage() != OBJ_PHYSICAL {
                    return Err(VerifyError::ObjectMismatch {
                        paddr: cab_paddr,
                        field: "chunk-info address block storage class",
                        expected: OBJ_PHYSICAL as u64,
                        observed: cab.storage() as u64,
                    });
                }
                if u32_at(&cab.bytes, 0x20) as usize != cab_index {
                    return Err(VerifyError::ObjectMismatch {
                        paddr: cab_paddr,
                        field: "chunk-info address block index",
                        expected: cab_index as u64,
                        observed: u32_at(&cab.bytes, 0x20) as u64,
                    });
                }
                let entries = u32_at(&cab.bytes, 0x24) as usize;
                let expected_entries = if cab_index + 1 == cab_count {
                    cib_count - cab_index * cibs_per_cab
                } else {
                    cibs_per_cab
                };
                if entries != expected_entries {
                    return Err(VerifyError::FieldMismatch {
                        what: "chunk-info address block entry count",
                        expected: expected_entries as u64,
                        observed: entries as u64,
                    });
                }
                if 0x28 + entries * 8 > self.block_size {
                    return Err(VerifyError::NodeMalformed {
                        paddr: cab_paddr,
                        reason: "chunk-info address block holds more entries than it can",
                    });
                }
                for entry in 0..entries {
                    addrs.push(u64_at(&cab.bytes, 0x28 + entry * 8));
                }
            }
            addrs
        };

        let mut bitmaps: Vec<Option<Vec<u8>>> = Vec::new();
        let mut counted_free = 0u64;
        let mut covered = 0u64;
        let mut seen_chunks = 0u64;
        for (cib_index, &cib_paddr) in cib_addrs.iter().enumerate() {
            if !in_internal_pool(cib_paddr) {
                return Err(VerifyError::AddressOutsideInternalPool {
                    paddr: cib_paddr,
                    what: "chunk info block",
                });
            }
            let cib = self.read_expecting(
                cib_paddr,
                Some(cib_paddr),
                TYPE_SPACEMAN_CIB,
                "chunk info block",
            )?;
            if cib.storage() != OBJ_PHYSICAL {
                return Err(VerifyError::ObjectMismatch {
                    paddr: cib_paddr,
                    field: "chunk info block storage class",
                    expected: OBJ_PHYSICAL as u64,
                    observed: cib.storage() as u64,
                });
            }
            if u32_at(&cib.bytes, 0x20) as usize != cib_index {
                return Err(VerifyError::ObjectMismatch {
                    paddr: cib_paddr,
                    field: "chunk info block index",
                    expected: cib_index as u64,
                    observed: u32_at(&cib.bytes, 0x20) as u64,
                });
            }
            let chunks = u32_at(&cib.bytes, 0x24) as u64;
            if chunks > chunks_per_cib {
                return Err(VerifyError::NodeMalformed {
                    paddr: cib_paddr,
                    reason: "chunk info block holds more chunks than its own limit",
                });
            }
            for slot in 0..chunks as usize {
                let at = 0x28 + slot * CHUNK_INFO_BYTES;
                let chunk_addr = u64_at(&cib.bytes, at + 8);
                let chunk_blocks = u32_at(&cib.bytes, at + 16);
                let recorded = u32_at(&cib.bytes, at + 20);
                let bitmap_addr = u64_at(&cib.bytes, at + 24);
                if chunk_addr != covered {
                    return Err(VerifyError::ChunkCoverage {
                        covered: chunk_addr,
                        block_count: covered,
                    });
                }
                if chunk_blocks as u64 > blocks_per_chunk {
                    return Err(VerifyError::FieldOutOfRange {
                        what: "chunk block count",
                        observed: chunk_blocks as u64,
                    });
                }
                // A zero ci_bitmap_addr means the chunk is entirely free, not that its bitmap is at block zero.
                let bitmap = if bitmap_addr == 0 {
                    None
                } else {
                    if !in_internal_pool(bitmap_addr) {
                        return Err(VerifyError::AddressOutsideInternalPool {
                            paddr: bitmap_addr,
                            what: "allocation bitmap",
                        });
                    }
                    let bitmap = self.read_raw(bitmap_addr)?;
                    self.note(bitmap_addr, "allocation bitmap");
                    Some(bitmap)
                };
                let free = match &bitmap {
                    None => chunk_blocks,
                    Some(bitmap) => {
                        let mut free = 0u32;
                        for bit in 0..chunk_blocks as usize {
                            if bitmap[bit >> 3] >> (bit & 7) & 1 == 0 {
                                free += 1;
                            }
                        }
                        free
                    }
                };
                if free != recorded {
                    return Err(VerifyError::ChunkFreeCountMismatch {
                        chunk_addr,
                        recorded,
                        counted: free,
                    });
                }
                counted_free += free as u64;
                covered += chunk_blocks as u64;
                seen_chunks += 1;
                bitmaps.push(bitmap);
            }
        }
        if seen_chunks != chunk_count {
            return Err(VerifyError::ChunkCoverage {
                covered: seen_chunks,
                block_count: chunk_count,
            });
        }
        if covered != self.block_count {
            return Err(VerifyError::ChunkCoverage {
                covered,
                block_count: self.block_count,
            });
        }
        if counted_free != recorded_free {
            return Err(VerifyError::FreeCountMismatch {
                recorded: recorded_free,
                counted: counted_free,
            });
        }

        let mut free_queue_tree_oids = Vec::new();
        for queue in 0..3usize {
            let oid = u64_at(sm, 0xC8 + queue * 40 + 8);
            if oid != 0 {
                free_queue_tree_oids.push(oid);
            }
        }

        Ok(Allocation {
            blocks_per_chunk,
            bitmaps,
            free_block_count: counted_free,
            free_queue_tree_oids,
        })
    }
}

// fsck_apfs -n accepts a tight-packed, unaligned layout; the live kernel mount path refuses it (Container ERROR -69808).
const fn align8(v: u32) -> u32 {
    (v + 7) & !7
}

// The free chain terminates with 0xFFFF (not 0), and every live, off-chain slot holds 0xFFFF too.
fn verify_ip_ring(
    sm: &[u8],
    size_in_blocks: u64,
    ring_blocks: u64,
    xid: u64,
) -> Result<u32, VerifyError> {
    if size_in_blocks == 0 || ring_blocks == 0 || size_in_blocks > ring_blocks {
        return Err(VerifyError::RingBroken {
            reason: "the ring is smaller than the bitmap it must hold",
        });
    }
    let xid_offset = u32_at(sm, 0x144);
    let bitmap_offset = u32_at(sm, 0x148);
    let next_offset = u32_at(sm, 0x14C);
    if xid_offset < SPACEMAN_STRUCT_SIZE {
        return Err(VerifyError::RingBroken {
            reason: "the transaction id array overlaps the fixed structure",
        });
    }
    let expected_bitmap_offset = align8(xid_offset + size_in_blocks as u32 * 8);
    if bitmap_offset != expected_bitmap_offset {
        return Err(VerifyError::FieldMismatch {
            what: "sm_ip_bitmap_offset",
            expected: expected_bitmap_offset as u64,
            observed: bitmap_offset as u64,
        });
    }
    let expected_next_offset = align8(bitmap_offset + size_in_blocks as u32 * 2);
    if next_offset != expected_next_offset {
        return Err(VerifyError::FieldMismatch {
            what: "sm_ip_bm_free_next_offset",
            expected: expected_next_offset as u64,
            observed: next_offset as u64,
        });
    }
    let (xid_offset, bitmap_offset, next_offset) = (
        xid_offset as usize,
        bitmap_offset as usize,
        next_offset as usize,
    );
    if next_offset + ring_blocks as usize * 2 > sm.len() {
        return Err(VerifyError::RingBroken {
            reason: "the free chain array leaves the space manager object",
        });
    }

    let mut live = Vec::new();
    for slot in 0..size_in_blocks as usize {
        let index = u16_at(sm, bitmap_offset + slot * 2);
        if index as u64 >= ring_blocks {
            return Err(VerifyError::RingBroken {
                reason: "a live bitmap names a ring slot that does not exist",
            });
        }
        if live.contains(&index) {
            return Err(VerifyError::RingBroken {
                reason: "two live bitmaps name the same ring slot",
            });
        }
        if u64_at(sm, xid_offset + slot * 8) > xid {
            return Err(VerifyError::RingBroken {
                reason: "a live bitmap is newer than the checkpoint being mounted",
            });
        }
        live.push(index);
    }

    let head = u16_at(sm, 0x140);
    let tail = u16_at(sm, 0x142);
    let mut visited: Vec<u16> = Vec::new();
    let mut cursor = head;
    while cursor != BTOFF_INVALID {
        if cursor as u64 >= ring_blocks {
            return Err(VerifyError::RingBroken {
                reason: "the free chain leaves the ring",
            });
        }
        if visited.contains(&cursor) {
            return Err(VerifyError::RingBroken {
                reason: "the free chain is cyclic",
            });
        }
        if live.contains(&cursor) {
            return Err(VerifyError::RingBroken {
                reason: "a live bitmap slot is on the free chain",
            });
        }
        visited.push(cursor);
        let next = u16_at(sm, next_offset + cursor as usize * 2);
        if next == BTOFF_INVALID && cursor != tail {
            return Err(VerifyError::RingBroken {
                reason: "the free chain ends somewhere other than the tail",
            });
        }
        cursor = next;
    }
    if visited.len() as u64 != ring_blocks - size_in_blocks {
        return Err(VerifyError::RingBroken {
            reason: "the free chain does not cover every slot that is not live",
        });
    }
    for index in &live {
        if u16_at(sm, next_offset + *index as usize * 2) != BTOFF_INVALID {
            return Err(VerifyError::RingBroken {
                reason: "a live bitmap slot carries a chain pointer",
            });
        }
    }
    Ok(next_offset as u32)
}

fn verify_reap_list(bytes: &[u8], block_size: usize) -> Result<(), VerifyError> {
    let max = u32_at(bytes, 0x2C) as usize;
    let count = u32_at(bytes, 0x30);
    let entry_bytes = 40usize;
    if max == 0 || 0x40 + max * entry_bytes > block_size {
        return Err(VerifyError::ReapListBroken {
            reason: "the entry array does not fit in its block",
        });
    }
    if count as usize > max {
        return Err(VerifyError::ReapListBroken {
            reason: "more entries are in use than the list holds",
        });
    }
    let mut cursor = u32_at(bytes, 0x3C);
    let mut visited = 0usize;
    while cursor != u32::MAX {
        if cursor as usize >= max || visited > max {
            return Err(VerifyError::ReapListBroken {
                reason: "the free chain leaves the entry array",
            });
        }
        visited += 1;
        cursor = u32_at(bytes, 0x40 + cursor as usize * entry_bytes);
    }
    if visited + count as usize != max {
        return Err(VerifyError::ReapListBroken {
            reason: "the free chain and the used count do not add up to the list size",
        });
    }
    Ok(())
}

impl Verifier<'_> {
    fn verify_volume(
        &mut self,
        oid: u64,
        paddr: u64,
        xid: u64,
    ) -> Result<VerifiedVolume, VerifyError> {
        let volume = self.read_expecting(paddr, Some(oid), TYPE_FS, "volume superblock")?;
        if volume.storage() != OBJ_VIRTUAL {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "volume storage class",
                expected: OBJ_VIRTUAL as u64,
                observed: volume.storage() as u64,
            });
        }
        let bytes = volume.bytes.clone();
        let magic = u32_at(&bytes, 0x20);
        if magic != APFS_MAGIC {
            return Err(VerifyError::BadMagic {
                paddr,
                observed: magic,
            });
        }

        let incompatible_features = u64_at(&bytes, 0x38);
        let sealed = incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0;
        let volume_omap_paddr = u64_at(&bytes, 0x80);
        let fs_tree_oid = u64_at(&bytes, 0x88);
        let extentref_tree_paddr = u64_at(&bytes, 0x90);
        let snap_meta_tree_paddr = u64_at(&bytes, 0x98);

        let integrity_meta_oid = u64_at(&bytes, APSB_INTEGRITY_META_OID_OFFSET);

        let omap_tree = self.read_omap(volume_omap_paddr, "volume object map")?;
        let entries = self.collect_omap(omap_tree, "volume object map tree")?;
        let fs_tree_paddr = resolve(&entries, fs_tree_oid, xid)?;

        let seal = if integrity_meta_oid == 0 {
            None
        } else {
            let paddr = resolve(&entries, integrity_meta_oid, xid)?;
            Some(self.read_volume_seal(oid, integrity_meta_oid, paddr)?)
        };

        for (tree_paddr, what) in [
            (extentref_tree_paddr, "extent reference tree"),
            (snap_meta_tree_paddr, "snapshot metadata tree"),
        ] {
            let tree = self.read_expecting(tree_paddr, Some(tree_paddr), TYPE_BTREE, what)?;
            if tree.storage() != OBJ_PHYSICAL {
                return Err(VerifyError::ObjectMismatch {
                    paddr: tree_paddr,
                    field: "tree storage class",
                    expected: OBJ_PHYSICAL as u64,
                    observed: tree.storage() as u64,
                });
            }
        }

        let root = Some(self.verify_fs_root(
            oid,
            fs_tree_paddr,
            DrecKeyLayout::of(incompatible_features),
            (!sealed).then_some(entries.as_slice()),
            xid,
        )?);

        let name_end = bytes[0x2C0..0x3C0]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        let name = String::from_utf8_lossy(&bytes[0x2C0..0x2C0 + name_end]).into_owned();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[0xF0..0x100]);

        Ok(VerifiedVolume {
            oid,
            paddr,
            fs_index: u32_at(&bytes, 0x24),
            name,
            role: u16_at(&bytes, 0x3C4),
            uuid,
            sealed,
            incompatible_features,
            read_only_compatible_features: u64_at(&bytes, 0x30),
            reserve_block_count: u64_at(&bytes, 0x48),
            quota_block_count: u64_at(&bytes, 0x50),
            fs_flags: u64_at(&bytes, 0x108),
            next_obj_id: u64_at(&bytes, 0xB0),
            fs_tree_oid,
            fs_tree_paddr,
            extentref_tree_paddr,
            snap_meta_tree_paddr,
            root,
            seal,
        })
    }

    fn read_volume_seal(
        &mut self,
        volume_oid: u64,
        oid: u64,
        paddr: u64,
    ) -> Result<VolumeSeal, VerifyError> {
        let object =
            self.read_expecting(paddr, Some(oid), TYPE_INTEGRITY_META, "integrity metadata")?;
        if object.storage() != OBJ_VIRTUAL {
            return Err(VerifyError::ObjectMismatch {
                paddr,
                field: "integrity metadata storage class",
                expected: OBJ_VIRTUAL as u64,
                observed: object.storage() as u64,
            });
        }
        decode_volume_seal(volume_oid, oid, paddr, &object.bytes)
    }

    fn verify_fs_root(
        &mut self,
        volume_oid: u64,
        paddr: u64,
        layout: DrecKeyLayout,
        omap: Option<&[OmapEntry]>,
        xid: u64,
    ) -> Result<VerifiedFsRoot, VerifyError> {
        let mut scan = FsRootScan::default();
        let mut visited = std::collections::HashSet::new();
        self.scan_fs_records(
            volume_oid,
            paddr,
            None,
            layout,
            omap,
            xid,
            &mut visited,
            &mut scan,
        )?;

        if scan.root_dir_mode.is_none() {
            return Err(VerifyError::RootDirectoryMissing {
                volume: volume_oid,
                reason: "no inode record for the root directory",
            });
        }
        if !scan.entries.iter().any(|(_, id)| *id == ROOT_DIR_INO_NUM) {
            return Err(VerifyError::RootDirectoryMissing {
                volume: volume_oid,
                reason: "no directory entry points at the root directory",
            });
        }

        Ok(VerifiedFsRoot {
            record_count: scan.record_count,
            entries: scan.entries,
            inodes: scan.inodes,
            root_dir_mode: scan.root_dir_mode,
            private_dir_mode: scan.private_dir_mode,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn scan_fs_records(
        &mut self,
        volume_oid: u64,
        paddr: u64,
        expected_level: Option<u16>,
        layout: DrecKeyLayout,
        omap: Option<&[OmapEntry]>,
        xid: u64,
        visited: &mut std::collections::HashSet<u64>,
        scan: &mut FsRootScan,
    ) -> Result<(), VerifyError> {
        if !visited.insert(paddr) {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "filesystem tree node was reached more than once",
            });
        }
        let sealed = omap.is_none();
        let object = if sealed {
            self.read_headerless_node(paddr)?
        } else {
            let (object_type, what) = match expected_level {
                None => (TYPE_BTREE, "filesystem tree root"),
                Some(_) => (TYPE_BTREE_NODE, "filesystem tree node"),
            };
            self.read_expecting(paddr, None, object_type, what)?
        };
        let node = BTreeNode::decode_node(&object, self.block_size, sealed)?;
        if let Some(level) = expected_level
            && node.level != level
        {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "filesystem tree node is not one level below its parent",
            });
        }
        let mut descend_into = Vec::new();
        let mut previous: Option<(u64, u64, RecordTail)> = None;

        for index in 0..node.nkeys {
            let (key, value) = node.entry(index)?;
            if key.len() < 8 {
                return Err(VerifyError::NodeMalformed {
                    paddr,
                    reason: "filesystem record key is shorter than its header",
                });
            }
            let header = u64_at(key, 0);
            let kind = header >> 60;
            let obj_id = header & 0x0FFF_FFFF_FFFF_FFFF;

            let tail = RecordTail::of(kind, key, layout);
            if let Some((previous_id, previous_kind, previous_tail)) = &previous {
                let ordered = (*previous_id, *previous_kind) < (obj_id, kind)
                    || ((*previous_id, *previous_kind) == (obj_id, kind) && *previous_tail < tail);
                if !ordered {
                    return Err(VerifyError::RecordsOutOfOrder { paddr, index });
                }
            }
            previous = Some((obj_id, kind, tail));

            if !node.is_leaf() {
                if value.len() < 8 {
                    return Err(VerifyError::NodeMalformed {
                        paddr,
                        reason: "filesystem tree index record has no child object id",
                    });
                }
                let child_paddr = match omap {
                    Some(entries) => resolve(entries, u64_at(value, 0), xid)?,
                    None => u64_at(value, 0),
                };
                descend_into.push(child_paddr);
                continue;
            }

            scan.record_count += 1;
            match kind {
                J_DIR_REC => {
                    if value.len() < 18 {
                        return Err(VerifyError::NodeMalformed {
                            paddr,
                            reason: "directory record is truncated",
                        });
                    }
                    let name_at = layout.name_offset();
                    let name_len = layout.name_length(key).ok_or(VerifyError::NodeMalformed {
                        paddr,
                        reason: "directory record key is shorter than its name length",
                    })?;
                    if name_len == 0 || name_at + name_len > key.len() {
                        return Err(VerifyError::NodeMalformed {
                            paddr,
                            reason: "directory record name length leaves the key",
                        });
                    }
                    if obj_id == ROOT_DIR_PARENT {
                        let name = String::from_utf8_lossy(&key[name_at..name_at + name_len - 1])
                            .into_owned();
                        scan.entries.push((name, u64_at(value, 0)));
                    }
                }
                J_INODE => {
                    if value.len() < 0x5C {
                        return Err(VerifyError::NodeMalformed {
                            paddr,
                            reason: "inode record is shorter than its fixed fields",
                        });
                    }
                    let mode = u16_at(value, 0x50);
                    if obj_id == ROOT_DIR_INO_NUM {
                        if u64_at(value, 0) != ROOT_DIR_PARENT {
                            return Err(VerifyError::RootDirectoryMissing {
                                volume: volume_oid,
                                reason: "the root inode's parent is not the root directory parent",
                            });
                        }
                        scan.root_dir_mode = Some(mode);
                    }
                    if obj_id == PRIV_DIR_INO_NUM {
                        scan.private_dir_mode = Some(mode);
                    }
                    scan.inodes.push(obj_id);
                }
                J_XATTR => validate_xattr_record(paddr, key, value)?,
                J_SIBLING_LINK => validate_sibling_link_record(paddr, key, value)?,
                J_CRYPTO_STATE => validate_crypto_state_record(paddr, value)?,
                _ => {}
            }
        }

        if node.is_leaf() {
            return Ok(());
        }
        if node.level == 0 {
            return Err(VerifyError::NodeMalformed {
                paddr,
                reason: "an index node claims to be at the leaf level",
            });
        }
        for child_paddr in descend_into {
            self.scan_fs_records(
                volume_oid,
                child_paddr,
                Some(node.level - 1),
                layout,
                omap,
                xid,
                visited,
                scan,
            )?;
        }
        Ok(())
    }
}

const XATTR_DATA_STREAM: u16 = 0x1;
const XATTR_DATA_EMBEDDED: u16 = 0x2;

fn validate_xattr_record(paddr: u64, key: &[u8], value: &[u8]) -> Result<(), VerifyError> {
    if key.len() < 10 {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "extended attribute key is shorter than its fixed fields",
        });
    }
    let name_len = u16_at(key, 8) as usize;
    if name_len == 0 || 10 + name_len != key.len() {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "extended attribute name length does not exactly fill the key",
        });
    }
    if value.len() < 4 {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "extended attribute value is shorter than its fixed fields",
        });
    }
    let flags = u16_at(value, 0);
    let xdata_len = u16_at(value, 2) as usize;
    let storage = flags & (XATTR_DATA_STREAM | XATTR_DATA_EMBEDDED);
    if storage != XATTR_DATA_STREAM && storage != XATTR_DATA_EMBEDDED {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "extended attribute flags name neither or both storage kinds",
        });
    }
    if storage == XATTR_DATA_EMBEDDED && 4 + xdata_len != value.len() {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "embedded extended attribute data length does not exactly fill the value",
        });
    }
    Ok(())
}

fn validate_sibling_link_record(paddr: u64, key: &[u8], value: &[u8]) -> Result<(), VerifyError> {
    if key.len() != 16 {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "sibling link key is not exactly a header and a sibling id",
        });
    }
    if value.len() < 10 {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "sibling link value is shorter than its fixed fields",
        });
    }
    let name_len = u16_at(value, 8) as usize;
    if name_len == 0 || 10 + name_len != value.len() {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "sibling link name length does not exactly fill the value",
        });
    }
    Ok(())
}

fn validate_crypto_state_record(paddr: u64, value: &[u8]) -> Result<(), VerifyError> {
    if value.len() < 24 {
        return Err(VerifyError::NodeMalformed {
            paddr,
            reason: "crypto state value is shorter than its fixed fields",
        });
    }
    Ok(())
}

#[derive(Default)]
struct FsRootScan {
    record_count: usize,
    entries: Vec<(String, u64)>,
    inodes: Vec<u64>,
    root_dir_mode: Option<u16>,
    private_dir_mode: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Range;

    const APFS_BLOCK_SIZE: u32 = 4096;

    fn verify(bytes: &[u8]) -> Result<VerifiedContainer, VerifyError> {
        let mut source = SliceBlocks::new(bytes, APFS_BLOCK_SIZE);
        verify_container(&mut source)
    }

    fn apple_capture_path() -> &'static str {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/apfs-094-56699-098.blocks"
        )
    }

    fn apple_unsealed_capture_path() -> &'static str {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/apfs-094-56453-088.blocks"
        )
    }

    const CAPTURE_MAGIC: &[u8; 8] = &[0x4d, 0x58, 0x41, 0x50, 0x46, 0x53, 0x46, 0x58];
    const CAPTURE_HEADER_BYTES: usize = 28;

    const CAPTURED_SUPERBLOCK: u64 = 1786;
    const CAPTURED_VOLUME: u64 = 5496;

    const CAPTURED_UNSEALED_SUPERBLOCK: u64 = 45_787;
    const CAPTURED_UNSEALED_VOLUME: u64 = 65_539;
    const CAPTURED_UNSEALED_FS_LEAF: u64 = 104_961;
    const CAPTURED_UNSEALED_EMPTY_CHUNK: u64 = 163_840;

    struct Capture {
        block_count: u64,
        block_size: usize,
        blocks: Vec<(u64, Vec<u8>)>,
    }

    impl Capture {
        fn apple() -> Option<Self> {
            Self::load_file(apple_capture_path())
        }

        fn apple_unsealed() -> Option<Self> {
            Self::load_file(apple_unsealed_capture_path())
        }

        fn load_file(path: &str) -> Option<Self> {
            match std::fs::read(path) {
                Ok(bytes) => Some(Self::load(&bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => panic!("{path} is present but unreadable: {error}"),
            }
        }

        fn load(bytes: &[u8]) -> Self {
            assert_eq!(&bytes[..8], CAPTURE_MAGIC, "capture magic");
            assert_eq!(u32_at(bytes, 8), 1, "capture version");
            let block_size = u32_at(bytes, 12) as usize;
            let block_count = u64_at(bytes, 16);
            let records = u32_at(bytes, 24) as usize;

            let mut blocks = Vec::with_capacity(records);
            let mut at = CAPTURE_HEADER_BYTES;
            for _ in 0..records {
                let index = u64_at(bytes, at);
                at += 8;
                blocks.push((index, bytes[at..at + block_size].to_vec()));
                at += block_size;
            }
            assert_eq!(at, bytes.len(), "capture has trailing bytes");
            assert!(
                blocks.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "capture is not sorted by address"
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
                .unwrap_or_else(|_| panic!("block {paddr} is not in the capture"))
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

        fn edit_unchecked(&mut self, paddr: u64, edit: impl FnOnce(&mut [u8])) {
            let slot = self.slot(paddr);
            edit(&mut self.blocks[slot].1);
        }

        fn verify(&mut self) -> Result<VerifiedContainer, VerifyError> {
            verify_container(self)
        }

        fn ephemeral_paddr(&mut self, o_type: u32) -> u64 {
            let verified = self.verify().expect("verify");
            verified
                .ephemeral
                .iter()
                .find(|(_, _, kind)| kind & OBJ_TYPE_MASK == o_type)
                .map(|(_, paddr, _)| *paddr)
                .unwrap_or_else(|| panic!("no ephemeral object of type {o_type:#x}"))
        }

        fn checkpoint_map_paddr(&self) -> u64 {
            let zero = self.block(0);
            let base = u64_at(zero, 0x70);
            let blocks = u32_at(zero, 0x68) as u64;
            (base..base + blocks)
                .find(|paddr| {
                    let o_type = u32_at(self.block(*paddr), 0x18);
                    o_type & OBJ_TYPE_MASK == TYPE_CHECKPOINT_MAP
                        && o_type & OBJ_STORAGE_MASK == OBJ_PHYSICAL
                })
                .expect("checkpoint map in the descriptor area")
        }
    }

    impl BlockSource for Capture {
        fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
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

    struct CaptureStream {
        capture: Capture,
        base: u64,
        at: u64,
    }

    impl CaptureStream {
        fn len(&self) -> u64 {
            self.base + self.capture.block_count * self.capture.block_size as u64
        }
    }

    impl Read for CaptureStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let len = self.len();
            let mut written = 0;
            while written < buf.len() && self.at < len {
                buf[written] = if self.at < self.base {
                    0
                } else {
                    let offset = self.at - self.base;
                    let index = offset / self.capture.block_size as u64;
                    let within = (offset % self.capture.block_size as u64) as usize;
                    match self
                        .capture
                        .blocks
                        .binary_search_by_key(&index, |(paddr, _)| *paddr)
                    {
                        Ok(slot) => self.capture.blocks[slot].1[within],
                        Err(_) => 0,
                    }
                };
                written += 1;
                self.at += 1;
            }
            Ok(written)
        }
    }

    impl Seek for CaptureStream {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            let at = match to {
                SeekFrom::Start(offset) => offset as i128,
                SeekFrom::End(offset) => self.len() as i128 + offset as i128,
                SeekFrom::Current(offset) => self.at as i128 + offset as i128,
            };
            if at < 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "seek before the start of the stream",
                ));
            }
            self.at = at as u64;
            Ok(self.at)
        }
    }

    fn reseal(block: &mut [u8]) {
        let mut low: u64 = 0;
        let mut high: u64 = 0;
        for word in block[8..].chunks_exact(4) {
            low = (low + u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64)
                % 0xFFFF_FFFF;
            high = (high + low) % 0xFFFF_FFFF;
        }
        let first = 0xFFFF_FFFF - ((low + high) % 0xFFFF_FFFF);
        let second = 0xFFFF_FFFF - ((low + first) % 0xFFFF_FFFF);
        block[0..8].copy_from_slice(&((second << 32) | first).to_le_bytes());
    }

    #[test]
    fn the_captured_apple_container_verifies_end_to_end() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let verified = capture.verify().expect("verify");

        assert_eq!(verified.block_size, APFS_BLOCK_SIZE);
        assert_eq!(verified.block_count, 65_024);
        assert_eq!(
            verified.uuid,
            [
                0x56, 0xFF, 0xD2, 0xDD, 0x24, 0x4C, 0x4D, 0xC2, 0xAD, 0x93, 0xF0, 0x1D, 0x4B, 0x2C,
                0xA6, 0x55
            ]
        );
        assert_eq!(verified.xid, 14);
        assert_eq!(verified.superblock_paddr, CAPTURED_SUPERBLOCK);
        assert_eq!(verified.max_file_systems, 1);
        assert_eq!(verified.free_block_count, 13_121);
        assert_eq!(verified.ephemeral.len(), 5);
        assert_eq!(verified.objects_checked, 29);
        assert_eq!(verified.blocks_in_use.len(), 26);

        assert_eq!(verified.volumes.len(), 1);
        let volume = &verified.volumes[0];
        assert_eq!(volume.name, "CheerF25F80.UniversalMacExclaveOS");
        assert_eq!(volume.oid, 1026);
        assert_eq!(volume.paddr, CAPTURED_VOLUME);
        assert_eq!(volume.fs_index, 0);
        assert_eq!(
            volume.uuid,
            [
                0xFA, 0x2D, 0xF5, 0x46, 0xD0, 0x4C, 0x42, 0x83, 0x89, 0x71, 0x0B, 0x4F, 0x2F, 0x43,
                0x28, 0xD4
            ]
        );
        assert!(volume.sealed);
        assert_eq!(
            volume.incompatible_features & APFS_INCOMPAT_SEALED_VOLUME,
            APFS_INCOMPAT_SEALED_VOLUME
        );
        assert_eq!(volume.read_only_compatible_features, 0);
        assert_eq!(volume.reserve_block_count, 0);
        assert_eq!(volume.quota_block_count, 0);
        assert_eq!(volume.fs_tree_oid, 1292);
        assert_eq!(volume.extentref_tree_paddr, 1323);
        assert_eq!(volume.snap_meta_tree_paddr, 1325);
        assert_eq!(volume.root, None);

        let seal = volume.seal.as_ref().expect("sealed volume carries a seal");
        assert_eq!(seal.hash_type, 1);
        assert_eq!(seal.hash_name, "sha256");
        assert!(!seal.broken);
        assert_eq!(
            seal.root_hash_hex(),
            "824CED64D9D558850EE49C09B3D6D27BA318CDA70E9D49C7F69B7976E48DF54B"
        );
    }

    #[test]
    fn the_seal_read_agrees_with_the_full_verifier_on_the_captured_container() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let verified = capture.verify().expect("verify");
        let read = read_container_seals(&mut capture).expect("seal read");

        assert_eq!(read.block_size, verified.block_size);
        assert_eq!(read.block_count, verified.block_count);
        assert_eq!(read.uuid, verified.uuid);
        assert_eq!(read.xid, verified.xid);
        assert_eq!(read.superblock_paddr, verified.superblock_paddr);
        assert_eq!(read.volumes.len(), verified.volumes.len());

        for (report, volume) in read.volumes.iter().zip(&verified.volumes) {
            assert_eq!(report.oid, volume.oid);
            assert_eq!(report.paddr, volume.paddr);
            assert_eq!(report.fs_index, volume.fs_index);
            assert_eq!(report.name, volume.name);
            assert_eq!(report.role, volume.role);
            assert_eq!(report.uuid, volume.uuid);
            assert_eq!(report.sealed, volume.sealed);
            assert_eq!(report.seal, volume.seal);
        }
    }

    #[test]
    fn a_container_whose_block_zero_is_not_apfs_is_refused_by_the_seal_read() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        capture.edit(0, |block| block[0x20..0x24].fill(0));
        assert!(matches!(
            read_container_seals(&mut capture),
            Err(VerifyError::BadMagic { paddr: 0, .. })
        ));
    }

    #[test]
    fn the_verifier_streams_a_container_out_of_an_image_at_an_offset() {
        let base = 24_576u64;
        let Some(capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let stream = CaptureStream {
            capture,
            base,
            at: 0,
        };
        let mut source = ReaderBlocks::new(stream, base, APFS_BLOCK_SIZE);
        let verified = verify_container(&mut source).expect("verify");
        assert_eq!(verified.block_count, 65_024);
        assert_eq!(verified.superblock_paddr, CAPTURED_SUPERBLOCK);
        assert_eq!(verified.volumes.len(), 1);
        assert!(verified.volumes[0].sealed);
    }

    fn apple_base_system_integrity_meta() -> Vec<u8> {
        const ROOT_HASH: [u8; 32] = [
            0x42, 0x04, 0x4A, 0x58, 0xD0, 0xF2, 0xFB, 0x07, 0x71, 0xBE, 0xF9, 0x71, 0x3C, 0x76,
            0x8F, 0xE5, 0x98, 0xFB, 0xF3, 0x42, 0xDC, 0x7B, 0x0E, 0x7E, 0x5F, 0xBC, 0xD7, 0x7F,
            0x88, 0x58, 0x95, 0x31,
        ];
        let mut bytes = vec![0u8; APFS_BLOCK_SIZE as usize];
        bytes[IM_VERSION_OFFSET..IM_VERSION_OFFSET + 4].copy_from_slice(&2u32.to_le_bytes());
        bytes[IM_FLAGS_OFFSET..IM_FLAGS_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[IM_HASH_TYPE_OFFSET..IM_HASH_TYPE_OFFSET + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[IM_ROOT_HASH_OFFSET_OFFSET..IM_ROOT_HASH_OFFSET_OFFSET + 4]
            .copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x80 + ROOT_HASH.len()].copy_from_slice(&ROOT_HASH);
        bytes
    }

    #[test]
    fn apples_own_integrity_metadata_decodes_to_the_hash_it_ships_in_the_auth_blob() {
        let seal = decode_volume_seal(1024, 7962, 6361, &apple_base_system_integrity_meta())
            .expect("decode");

        assert_eq!(seal.oid, 7962);
        assert_eq!(seal.paddr, 6361);
        assert_eq!(seal.version, 2);
        assert_eq!(seal.flags, 0);
        assert!(!seal.broken);
        assert_eq!(seal.broken_xid, 0);
        assert_eq!(seal.hash_type, 1);
        assert_eq!(seal.hash_name, "sha256");
        assert_eq!(seal.root_hash_offset, 0x80);
        assert_eq!(seal.root_hash.len(), 32);
        assert_eq!(
            seal.root_hash_hex(),
            "42044A58D0F2FB0771BEF9713C768FE598FBF342DC7B0E7E5FBCD77F88589531"
        );
    }

    #[test]
    fn the_snapshot_name_is_the_prefix_and_the_hash_in_uppercase_hex() {
        let seal = decode_volume_seal(1024, 7962, 6361, &apple_base_system_integrity_meta())
            .expect("decode");

        assert_eq!(
            seal.root_snapshot_name(),
            "com.apple.os.update-42044A58D0F2FB0771BEF9713C768FE598FBF342DC7B0E7E5FBCD77F88589531"
        );
        assert_eq!(
            seal.root_snapshot_name().len(),
            ROOT_SNAPSHOT_PREFIX.len() + 2 * 32
        );
    }

    fn btree_leaf_block(
        block_size: usize,
        level: u16,
        leaf: bool,
        records: &[(Vec<u8>, Vec<u8>)],
    ) -> Vec<u8> {
        let mut block = vec![0u8; block_size];
        let flags: u16 = if leaf { BTNODE_LEAF } else { 0 };
        block[0x20..0x22].copy_from_slice(&flags.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&level.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&(records.len() as u32).to_le_bytes());
        let toc_len = (records.len() * 8) as u16;
        block[0x28..0x2A].copy_from_slice(&0u16.to_le_bytes());
        block[0x2A..0x2C].copy_from_slice(&toc_len.to_le_bytes());

        let toc = BTNODE_TOC_BASE;
        let key_base = toc + toc_len as usize;
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
            block[key_at..key_at + key.len()].copy_from_slice(key);
            key_cursor += key.len();

            let value_at = block_size - value_offset;
            block[value_at..value_at + value.len()].copy_from_slice(value);
            value_cursor = value_offset;
        }
        block
    }

    fn snapshot_metadata_record(xid: u64, name: &str, sblock_oid: u64) -> (Vec<u8>, Vec<u8>) {
        let key = ((J_SNAP_METADATA << 60) | xid).to_le_bytes().to_vec();
        let mut value = vec![0u8; 0x32];
        value[0x00..0x08].copy_from_slice(&0x1234_u64.to_le_bytes());
        value[0x08..0x10].copy_from_slice(&sblock_oid.to_le_bytes());
        value[0x10..0x18].copy_from_slice(&11_u64.to_le_bytes());
        value[0x18..0x20].copy_from_slice(&22_u64.to_le_bytes());
        value[0x20..0x28].copy_from_slice(&33_u64.to_le_bytes());
        value[0x2C..0x30].copy_from_slice(&0x1_u32.to_le_bytes());
        value[0x30..0x32].copy_from_slice(&((name.len() + 1) as u16).to_le_bytes());
        value.extend_from_slice(name.as_bytes());
        value.push(0);
        (key, value)
    }

    fn snapshot_name_record(name: &str, xid: u64) -> (Vec<u8>, Vec<u8>) {
        let mut key = (J_SNAP_NAME << 60).to_le_bytes().to_vec();
        key.extend_from_slice(&((name.len() + 1) as u16).to_le_bytes());
        key.extend_from_slice(name.as_bytes());
        key.push(0);
        (key, xid.to_le_bytes().to_vec())
    }

    #[test]
    fn a_snapshot_leaf_yields_both_the_metadata_record_and_the_name_record() {
        let name = "com.apple.os.update-\
                    E665088689556947ADF621B0053B4CA1662AEB6729590B5A5D43C3166FC1CE8F";
        let block = btree_leaf_block(
            4096,
            0,
            true,
            &[
                snapshot_metadata_record(0x2BF, name, 0x9A),
                snapshot_name_record(name, 0x2BF),
            ],
        );
        let object = Object {
            paddr: 7,
            bytes: block,
        };
        let node = BTreeNode::decode(&object, 4096).expect("decode leaf");
        let mut found = VolumeSnapshots::default();
        let mut children = Vec::new();
        take_snapshot_records(&node, &mut found, &mut children).expect("read records");

        assert!(children.is_empty(), "a leaf names no children");
        assert_eq!(found.snapshots.len(), 1);
        assert_eq!(found.snapshots[0].name, name);
        assert_eq!(found.snapshots[0].xid, 0x2BF);
        assert_eq!(found.snapshots[0].sblock_oid, 0x9A);
        assert_eq!(found.snapshots[0].flags, 1);
        assert_eq!(found.names, vec![(name.to_string(), 0x2BF)]);
        assert_eq!(found.xid_for_name(name), Some(0x2BF));
        assert_eq!(found.xid_for_name("com.apple.os.update-0000"), None);
        assert_eq!(found.root_snapshot_name(), Some(name));
    }

    #[test]
    fn a_volume_with_no_snapshot_records_at_all_resolves_no_root_snapshot_name() {
        let found = VolumeSnapshots::default();
        assert_eq!(found.root_snapshot_name(), None);
    }

    #[test]
    fn a_snapshot_named_outside_the_root_prefix_is_not_offered_as_a_root_snapshot() {
        let name = "not-a-root-snapshot";
        let block = btree_leaf_block(4096, 0, true, &[snapshot_name_record(name, 0x10)]);
        let object = Object {
            paddr: 7,
            bytes: block,
        };
        let node = BTreeNode::decode(&object, 4096).expect("decode leaf");
        let mut found = VolumeSnapshots::default();
        let mut children = Vec::new();
        take_snapshot_records(&node, &mut found, &mut children).expect("read records");

        assert_eq!(found.root_snapshot_name(), None);
    }

    #[test]
    fn two_root_snapshot_name_records_resolve_to_the_one_with_the_highest_xid() {
        let older = "com.apple.os.update-AAAAAAAA";
        let newer = "com.apple.os.update-BBBBBBBB";
        let block = btree_leaf_block(
            4096,
            0,
            true,
            &[
                snapshot_name_record(older, 0x10),
                snapshot_name_record(newer, 0x20),
            ],
        );
        let object = Object {
            paddr: 7,
            bytes: block,
        };
        let node = BTreeNode::decode(&object, 4096).expect("decode leaf");
        let mut found = VolumeSnapshots::default();
        let mut children = Vec::new();
        take_snapshot_records(&node, &mut found, &mut children).expect("read records");

        assert_eq!(found.names.len(), 2);
        assert_eq!(found.root_snapshot_name(), Some(newer));
    }

    #[test]
    fn a_snapshot_index_node_yields_its_children_and_no_records() {
        let block = btree_leaf_block(
            4096,
            1,
            false,
            &[
                (
                    ((J_SNAP_METADATA << 60) | 1).to_le_bytes().to_vec(),
                    99u64.to_le_bytes().to_vec(),
                ),
                (
                    ((J_SNAP_METADATA << 60) | 500).to_le_bytes().to_vec(),
                    137u64.to_le_bytes().to_vec(),
                ),
            ],
        );
        let object = Object {
            paddr: 3,
            bytes: block,
        };
        let node = BTreeNode::decode(&object, 4096).expect("decode index");
        let mut found = VolumeSnapshots::default();
        let mut children = Vec::new();
        take_snapshot_records(&node, &mut found, &mut children).expect("read records");

        assert_eq!(children, vec![99, 137]);
        assert!(found.snapshots.is_empty());
        assert!(found.names.is_empty());
    }

    #[test]
    fn a_snapshot_name_that_runs_off_its_key_is_refused_rather_than_truncated() {
        let (mut key, value) = snapshot_name_record("com.apple.os.update-AB", 4);
        key[8..10].copy_from_slice(&4000u16.to_le_bytes());
        let block = btree_leaf_block(4096, 0, true, &[(key, value)]);
        let object = Object {
            paddr: 11,
            bytes: block,
        };
        let node = BTreeNode::decode(&object, 4096).expect("decode leaf");
        let mut found = VolumeSnapshots::default();
        let mut children = Vec::new();
        let error = take_snapshot_records(&node, &mut found, &mut children)
            .expect_err("a name length that leaves the key is a malformed node");
        assert!(matches!(
            error,
            VerifyError::NodeMalformed { paddr: 11, .. }
        ));
    }

    const APPLE_CSYS_ROOT_HASH_TICKET_PAYLOAD: [u8; 0xD0] = [
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        0x00, 0x42, 0x04, 0x4A, 0x58, 0xD0, 0xF2, 0xFB, 0x07, 0x71, 0xBE, 0xF9, 0x71, 0x3C, 0x76,
        0x8F, 0xE5, 0x98, 0xFB, 0xF3, 0x42, 0xDC, 0x7B, 0x0E, 0x7E, 0x5F, 0xBC, 0xD7, 0x7F, 0x88,
        0x58, 0x95, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn encoding_apples_own_seal_reproduces_her_own_ticket_byte_for_byte() {
        let seal = decode_volume_seal(1024, 7962, 6361, &apple_base_system_integrity_meta())
            .expect("decode");
        assert_eq!(seal.version, 2);
        assert_eq!(seal.hash_type, 1);
        assert_eq!(
            seal.to_forwarded_root_hash_blob(),
            APPLE_CSYS_ROOT_HASH_TICKET_PAYLOAD.to_vec()
        );
    }

    #[test]
    fn the_forwarded_header_carries_the_volumes_own_version_and_hash_type() {
        let mut bytes = apple_base_system_integrity_meta();
        bytes[IM_VERSION_OFFSET..IM_VERSION_OFFSET + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[IM_HASH_TYPE_OFFSET..IM_HASH_TYPE_OFFSET + 4].copy_from_slice(&4u32.to_le_bytes());
        let seal = decode_volume_seal(1024, 7962, 6361, &bytes).expect("decode");
        assert_eq!(seal.version, 3);
        assert_eq!(seal.hash_type, 4);

        let blob = seal.to_forwarded_root_hash_blob();
        assert_eq!(u32::from_le_bytes(blob[0..4].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(blob[4..8].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(blob[8..12].try_into().unwrap()), 4);
        assert_eq!(
            u32::from_le_bytes(blob[12..16].try_into().unwrap()),
            seal.root_hash.len() as u32
        );
        assert_eq!(blob.len(), FORWARDED_ROOT_HASH_BLOB_BYTES);
        assert_eq!(blob[0x10..0x10 + seal.root_hash.len()], seal.root_hash[..]);
        assert!(blob[0x50..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn the_forwarded_blob_is_always_208_bytes_with_the_digest_at_0x10() {
        let seal = decode_volume_seal(1024, 7962, 6361, &apple_base_system_integrity_meta())
            .expect("decode");
        let blob = seal.to_forwarded_root_hash_blob();
        assert_eq!(blob.len(), FORWARDED_ROOT_HASH_BLOB_BYTES);
        assert_eq!(blob[0x10..0x10 + seal.root_hash.len()], seal.root_hash[..]);
        assert!(
            blob[0x10 + seal.root_hash.len()..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn a_seal_matches_only_the_digest_it_actually_stores() {
        let seal = decode_volume_seal(1024, 7962, 6361, &apple_base_system_integrity_meta())
            .expect("decode");

        assert!(seal.matches_digest(&seal.root_hash.clone()));
        let other = [
            0xE6, 0x65, 0x08, 0x86, 0x89, 0x55, 0x69, 0x47, 0xAD, 0xF6, 0x21, 0xB0, 0x05, 0x3B,
            0x4C, 0xA1, 0x66, 0x2A, 0xEB, 0x67, 0x29, 0x59, 0x0B, 0x5A, 0x5D, 0x43, 0xC3, 0x16,
            0x6F, 0xC1, 0xCE, 0x8F,
        ];
        assert!(!seal.matches_digest(&other));
        assert!(!seal.matches_digest(&seal.root_hash[..16]));
    }

    #[test]
    fn the_root_hash_is_read_from_the_offset_the_object_declares() {
        let mut bytes = apple_base_system_integrity_meta();
        let hash: Vec<u8> = bytes[0x80..0xA0].to_vec();
        bytes[0x80..0xA0].fill(0);
        bytes[0xC0..0xC0 + hash.len()].copy_from_slice(&hash);
        bytes[IM_ROOT_HASH_OFFSET_OFFSET..IM_ROOT_HASH_OFFSET_OFFSET + 4]
            .copy_from_slice(&0xC0u32.to_le_bytes());

        let seal = decode_volume_seal(1024, 7962, 6361, &bytes).expect("decode");
        assert_eq!(seal.root_hash, hash);
    }

    #[test]
    fn a_broken_seal_is_reported_as_broken_and_keeps_its_hash() {
        let mut bytes = apple_base_system_integrity_meta();
        bytes[IM_FLAGS_OFFSET..IM_FLAGS_OFFSET + 4]
            .copy_from_slice(&APFS_SEAL_BROKEN.to_le_bytes());
        bytes[IM_BROKEN_XID_OFFSET..IM_BROKEN_XID_OFFSET + 8]
            .copy_from_slice(&912u64.to_le_bytes());

        let seal = decode_volume_seal(1024, 7962, 6361, &bytes).expect("decode");
        assert!(seal.broken);
        assert_eq!(seal.broken_xid, 912);
        assert_eq!(seal.root_hash.len(), 32);
    }

    #[test]
    fn a_hash_type_this_build_cannot_size_is_refused_rather_than_guessed() {
        let mut bytes = apple_base_system_integrity_meta();
        bytes[IM_HASH_TYPE_OFFSET..IM_HASH_TYPE_OFFSET + 4].copy_from_slice(&99u32.to_le_bytes());

        assert_eq!(
            decode_volume_seal(1024, 7962, 6361, &bytes),
            Err(VerifyError::UnknownSealHashType {
                volume: 1024,
                hash_type: 99,
            })
        );
    }

    #[test]
    fn a_root_hash_that_leaves_the_object_is_refused() {
        let mut bytes = apple_base_system_integrity_meta();
        let past_the_end = APFS_BLOCK_SIZE - 8;
        bytes[IM_ROOT_HASH_OFFSET_OFFSET..IM_ROOT_HASH_OFFSET_OFFSET + 4]
            .copy_from_slice(&past_the_end.to_le_bytes());

        assert_eq!(
            decode_volume_seal(1024, 7962, 6361, &bytes),
            Err(VerifyError::SealRootHashOutOfRange {
                paddr: 6361,
                offset: past_the_end,
                length: 32,
            })
        );
    }

    #[test]
    fn every_hash_type_apfs_sealvolume_offers_has_a_length_within_the_slot() {
        for (number, name, length) in SEAL_HASH_LENGTHS {
            let resolved = seal_hash_type(number).expect("hash type resolves");
            assert_eq!(resolved, (name, length));
            assert!(
                length <= APFS_HASH_MAX_SIZE,
                "{name} does not fit the root hash slot"
            );
        }
        assert_eq!(seal_hash_type(0), None);
        assert_eq!(seal_hash_type(11), None);
    }

    #[test]
    fn a_blank_container_is_caught() {
        let bytes = vec![0u8; 4096 * APFS_BLOCK_SIZE as usize];
        assert!(matches!(
            verify(&bytes),
            Err(VerifyError::BadMagic { paddr: 0, .. })
        ));
    }

    #[test]
    fn a_corrupt_checksum_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        capture.edit_unchecked(0, |block| block[0x200] ^= 0x01);
        assert!(matches!(
            capture.verify(),
            Err(VerifyError::BadChecksum { paddr: 0 })
        ));
    }

    #[test]
    fn a_broken_internal_pool_ring_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let spaceman = capture.ephemeral_paddr(TYPE_SPACEMAN);
        capture.edit(spaceman, |block| {
            let next_offset = u32_at(block, 0x14C) as usize;
            let head = u16_at(block, 0x140);
            let second = u16_at(block, next_offset + head as usize * 2);
            let at = next_offset + second as usize * 2;
            block[at..at + 2].copy_from_slice(&head.to_le_bytes());
        });
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::RingBroken {
                reason: "the free chain is cyclic",
            }),
            "a cyclic free chain was accepted"
        );
    }

    #[test]
    fn a_live_ring_slot_left_on_the_free_chain_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let spaceman = capture.ephemeral_paddr(TYPE_SPACEMAN);
        capture.edit(spaceman, |block| {
            let bitmap_offset = u32_at(block, 0x148) as usize;
            let head = u16_at(block, 0x140);
            block[bitmap_offset..bitmap_offset + 2].copy_from_slice(&head.to_le_bytes());
        });
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::RingBroken {
                reason: "a live bitmap slot is on the free chain",
            }),
            "a live slot on the free chain was accepted"
        );
    }

    #[test]
    fn a_wrong_chunk_free_count_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let spaceman = capture.ephemeral_paddr(TYPE_SPACEMAN);
        let cib_paddr = {
            let block = capture.block(spaceman);
            u64_at(block, u32_at(block, 0x50) as usize)
        };
        capture.edit(cib_paddr, |block| {
            let recorded = u32_at(block, 0x28 + 20);
            block[0x28 + 20..0x28 + 24].copy_from_slice(&(recorded + 1).to_le_bytes());
        });
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::ChunkFreeCountMismatch {
                chunk_addr: 0,
                recorded: 2866,
                counted: 2865,
            }),
            "a wrong chunk free count was accepted"
        );
    }

    #[test]
    fn a_block_in_use_but_marked_free_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let verified = capture.verify().expect("verify");
        let volume_paddr = verified.volumes[0].paddr;
        assert_eq!(volume_paddr, CAPTURED_VOLUME);

        let spaceman = capture.ephemeral_paddr(TYPE_SPACEMAN);
        let (cib_paddr, blocks_per_chunk) = {
            let block = capture.block(spaceman);
            (
                u64_at(block, u32_at(block, 0x50) as usize),
                u32_at(block, 0x24) as u64,
            )
        };
        let chunk = (volume_paddr / blocks_per_chunk) as usize;
        let entry = 0x28 + chunk * CHUNK_INFO_BYTES;
        let bitmap_paddr = u64_at(capture.block(cib_paddr), entry + 24);

        let bit = (volume_paddr % blocks_per_chunk) as usize;
        capture.edit_unchecked(bitmap_paddr, |block| block[bit >> 3] &= !(1 << (bit & 7)));
        capture.edit(cib_paddr, |block| {
            let recorded = u32_at(block, entry + 20);
            block[entry + 20..entry + 24].copy_from_slice(&(recorded + 1).to_le_bytes());
        });
        capture.edit(spaceman, |block| {
            let free = u64_at(block, 0x48);
            block[0x48..0x50].copy_from_slice(&(free + 1).to_le_bytes());
        });

        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::BlockNotAllocated {
                paddr: CAPTURED_VOLUME,
                what: "volume superblock",
            }),
            "a live block marked free was accepted"
        );
    }

    #[test]
    fn an_ephemeral_object_missing_from_the_checkpoint_map_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let map_paddr = capture.checkpoint_map_paddr();
        capture.edit(map_paddr, |block| {
            let count = u32_at(block, 0x24);
            block[0x24..0x28].copy_from_slice(&(count - 1).to_le_bytes());
        });
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::UnmappedEphemeralOid { oid: 1818 }),
            "a missing ephemeral mapping was accepted"
        );
    }

    fn node_record(block: &[u8], index: usize) -> (Range<usize>, Range<usize>) {
        let flags = u16_at(block, 0x20);
        assert_eq!(
            flags & BTNODE_FIXED_KV_SIZE,
            0,
            "a filesystem tree node stores its own key and value lengths"
        );
        let toc = BTNODE_TOC_BASE + u16_at(block, 0x28) as usize;
        let key_base = toc + u16_at(block, 0x2A) as usize;
        let value_end = block.len()
            - if flags & BTNODE_ROOT != 0 {
                BTREE_INFO_BYTES
            } else {
                0
            };
        let at = toc + index * 8;
        let key_at = key_base + u16_at(block, at) as usize;
        let value_at = value_end - u16_at(block, at + 4) as usize;
        (
            key_at..key_at + u16_at(block, at + 2) as usize,
            value_at..value_at + u16_at(block, at + 6) as usize,
        )
    }

    fn node_record_for(block: &[u8], header: u64) -> usize {
        let nkeys = u32_at(block, 0x24) as usize;
        (0..nkeys)
            .find(|index| {
                let (key, _) = node_record(block, *index);
                u64_at(block, key.start) == header
            })
            .unwrap_or_else(|| panic!("no record with key header {header:#x} in the node"))
    }

    #[test]
    fn the_captured_unsealed_apple_container_verifies_end_to_end() {
        let Some(mut capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let verified = capture.verify().expect("verify");

        assert_eq!(verified.block_size, APFS_BLOCK_SIZE);
        assert_eq!(verified.block_count, 3_191_296);
        assert_eq!(verified.xid, 692);
        assert_eq!(verified.superblock_paddr, CAPTURED_UNSEALED_SUPERBLOCK);
        assert_eq!(verified.max_file_systems, 25);
        assert_eq!(verified.free_block_count, 110_566);
        assert_eq!(verified.ephemeral.len(), 5);
        assert_eq!(verified.objects_checked, 530);
        assert_eq!(verified.blocks_in_use.len(), 621);

        assert_eq!(verified.volumes.len(), 1);
        let volume = &verified.volumes[0];
        assert_eq!(volume.name, "Macintosh HD");
        assert_eq!(volume.oid, 1026);
        assert_eq!(volume.paddr, CAPTURED_UNSEALED_VOLUME);
        assert_eq!(volume.fs_index, 0);
        assert_eq!(volume.role, 0x1);
        assert!(!volume.sealed);
        assert_eq!(volume.seal, None);
        assert_eq!(volume.incompatible_features, APFS_INCOMPAT_CASE_INSENSITIVE);
        assert_eq!(volume.fs_tree_oid, 1028);
        assert_eq!(volume.fs_tree_paddr, 95_114);

        let root = volume.root.as_ref().expect("an unsealed volume is walked");
        assert_eq!(root.record_count, 64);
        assert_eq!(
            root.entries,
            vec![
                ("private-dir".to_string(), PRIV_DIR_INO_NUM),
                ("root".to_string(), ROOT_DIR_INO_NUM),
            ]
        );
        assert_eq!(root.root_dir_mode, Some(0o40755));
        assert_eq!(root.private_dir_mode, Some(0o40644));
        assert_eq!(root.inodes[0], ROOT_DIR_INO_NUM);
        assert_eq!(root.inodes[1], PRIV_DIR_INO_NUM);
    }

    #[test]
    fn a_chunk_with_no_bitmap_block_is_entirely_free_and_its_count_is_still_checked() {
        let Some(mut capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let spaceman = capture.ephemeral_paddr(TYPE_SPACEMAN);
        let (cib_paddr, blocks_per_chunk) = {
            let block = capture.block(spaceman);
            (
                u64_at(block, u32_at(block, 0x50) as usize),
                u32_at(block, 0x24) as u64,
            )
        };
        let slot = (CAPTURED_UNSEALED_EMPTY_CHUNK / blocks_per_chunk) as usize;
        let entry = 0x28 + slot * CHUNK_INFO_BYTES;
        {
            let cib = capture.block(cib_paddr);
            assert_eq!(u64_at(cib, entry + 8), CAPTURED_UNSEALED_EMPTY_CHUNK);
            assert_eq!(
                u64_at(cib, entry + 24),
                0,
                "the capture must carry a chunk with no bitmap block for this to mean anything"
            );
            assert_eq!(u32_at(cib, entry + 16), blocks_per_chunk as u32);
            assert_eq!(u32_at(cib, entry + 20), blocks_per_chunk as u32);
        }

        capture.edit(cib_paddr, |block| {
            let recorded = u32_at(block, entry + 20);
            block[entry + 20..entry + 24].copy_from_slice(&(recorded - 1).to_le_bytes());
        });
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::ChunkFreeCountMismatch {
                chunk_addr: CAPTURED_UNSEALED_EMPTY_CHUNK,
                recorded: blocks_per_chunk as u32 - 1,
                counted: blocks_per_chunk as u32,
            }),
            "a wrong free count on a chunk with no bitmap was accepted"
        );
    }

    #[test]
    fn a_reaper_that_holds_no_list_is_not_asked_to_resolve_one() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let reaper = capture.ephemeral_paddr(TYPE_NX_REAPER);
        assert_ne!(
            u64_at(capture.block(reaper), 0x30),
            0,
            "every shipped container has already reaped something"
        );
        capture.edit(reaper, |block| {
            block[0x30..0x40].fill(0);
            block[0x44..0x48].fill(0);
        });
        capture
            .verify()
            .expect("a container whose reaper holds no list must still verify");
    }

    #[test]
    fn a_reaper_whose_list_count_disagrees_with_its_head_is_caught() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let reaper = capture.ephemeral_paddr(TYPE_NX_REAPER);
        capture.edit(reaper, |block| block[0x44..0x48].fill(0));
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::ReapListBroken {
                reason: "the reaper's list count and its head and tail disagree about whether a list exists",
            }),
            "a reaper that contradicts itself was accepted"
        );
    }

    #[test]
    fn a_directory_record_key_is_read_in_the_layout_the_volume_declares() {
        let Some(capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let block = capture.block(CAPTURED_UNSEALED_FS_LEAF);
        let index = node_record_for(block, (J_DIR_REC << 60) | ROOT_DIR_PARENT);
        let (key, _) = node_record(block, index);
        let key = &block[key];

        assert_eq!(
            DrecKeyLayout::of(APFS_INCOMPAT_CASE_INSENSITIVE),
            DrecKeyLayout::Hashed
        );
        assert_eq!(
            DrecKeyLayout::of(APFS_INCOMPAT_NORMALIZATION_INSENSITIVE),
            DrecKeyLayout::Hashed
        );
        assert_eq!(
            DrecKeyLayout::of(APFS_INCOMPAT_CASE_INSENSITIVE | APFS_INCOMPAT_SEALED_VOLUME),
            DrecKeyLayout::Hashed
        );
        assert_eq!(
            DrecKeyLayout::of(APFS_INCOMPAT_SEALED_VOLUME),
            DrecKeyLayout::Plain
        );
        assert_eq!(DrecKeyLayout::of(0), DrecKeyLayout::Plain);

        let hashed = DrecKeyLayout::Hashed;
        assert_eq!(hashed.name_length(key), Some(12));
        assert_eq!(&key[hashed.name_offset()..key.len() - 1], b"private-dir");
        assert_eq!(u32_at(key, 8) >> 10, 0x2B_29A3);

        let plain = DrecKeyLayout::Plain;
        assert_eq!(plain.name_length(key), Some(35_852));
        assert!(plain.name_offset() + 35_852 > key.len());

        let mut as_plain = key[..8].to_vec();
        as_plain.extend_from_slice(&12u16.to_le_bytes());
        as_plain.extend_from_slice(&key[hashed.name_offset()..]);
        assert_eq!(plain.name_length(&as_plain), Some(12));
        assert_eq!(
            &as_plain[plain.name_offset()..as_plain.len() - 1],
            b"private-dir"
        );
    }

    #[test]
    fn hashed_directory_records_are_ordered_by_their_hash_and_not_by_their_name() {
        let Some(capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let block = capture.block(CAPTURED_UNSEALED_FS_LEAF);
        let nkeys = u32_at(block, 0x24) as usize;

        let mut names = Vec::new();
        let mut tails = Vec::new();
        for index in 0..nkeys {
            let (key, _) = node_record(block, index);
            let key = &block[key];
            let header = u64_at(key, 0);
            if header >> 60 != J_DIR_REC || header & 0x0FFF_FFFF_FFFF_FFFF != ROOT_DIR_INO_NUM {
                continue;
            }
            let length = DrecKeyLayout::Hashed.name_length(key).expect("name length");
            let at = DrecKeyLayout::Hashed.name_offset();
            names.push(key[at..at + length - 1].to_vec());
            tails.push(RecordTail::of(J_DIR_REC, key, DrecKeyLayout::Hashed));
        }
        assert!(
            names.len() > 2,
            "the root directory has entries in this leaf"
        );

        assert!(
            names.windows(2).any(|pair| pair[0] > pair[1]),
            "the entries would have to be out of alphabetical order for this to mean anything"
        );
        assert!(
            tails.windows(2).all(|pair| pair[0] < pair[1]),
            "the entries are not in the order their keys sort in"
        );
    }

    #[test]
    fn a_root_inode_that_names_the_wrong_parent_is_caught() {
        let Some(mut capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let parent_at = {
            let block = capture.block(CAPTURED_UNSEALED_FS_LEAF);
            let index = node_record_for(block, (J_INODE << 60) | ROOT_DIR_INO_NUM);
            let (_, value) = node_record(block, index);
            assert_eq!(
                u64_at(block, value.start),
                ROOT_DIR_PARENT,
                "the root inode's parent is the root directory parent"
            );
            value.start
        };
        capture.edit(CAPTURED_UNSEALED_FS_LEAF, |block| block[parent_at] = 4);
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::RootDirectoryMissing {
                volume: 1026,
                reason: "the root inode's parent is not the root directory parent",
            }),
            "a root inode hanging off the wrong parent was accepted"
        );
    }

    #[test]
    fn a_root_directory_entry_that_points_elsewhere_is_caught() {
        let Some(mut capture) = Capture::apple_unsealed() else {
            eprintln!("skipped: {} is not present", apple_unsealed_capture_path());
            return;
        };
        let file_id_at = {
            let block = capture.block(CAPTURED_UNSEALED_FS_LEAF);
            let mut found = None;
            for index in 0..u32_at(block, 0x24) as usize {
                let (key, value) = node_record(block, index);
                let key = &block[key.clone()];
                if u64_at(key, 0) != (J_DIR_REC << 60) | ROOT_DIR_PARENT {
                    continue;
                }
                if u64_at(block, value.start) == ROOT_DIR_INO_NUM {
                    found = Some(value.start);
                }
            }
            found.expect("an entry under the root directory parent names the root directory")
        };
        capture.edit(CAPTURED_UNSEALED_FS_LEAF, |block| block[file_id_at] = 9);
        assert_eq!(
            capture.verify().err(),
            Some(VerifyError::RootDirectoryMissing {
                volume: 1026,
                reason: "no directory entry points at the root directory",
            }),
            "a volume whose root directory has no entry was accepted"
        );
    }

    #[test]
    fn container_header_rejects_physical_storage_even_with_valid_checksum() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x18..0x1C].copy_from_slice(&(OBJ_PHYSICAL | TYPE_NX_SUPERBLOCK).to_le_bytes());
        crate::apfs_image::fletcher64_seal(&mut bytes);
        assert!(checksum_valid(&bytes));
        let object = Object { paddr: 0, bytes };
        assert!(matches!(
            validate_container_header(&object),
            Err(VerifyError::ObjectMismatch {
                field: "container superblock object type",
                ..
            })
        ));
    }

    #[test]
    fn checkpoint_bounds_require_map_and_superblock_and_bound_ring_indices() {
        let mut bytes = vec![0u8; 4096];
        bytes[0x68..0x6C].copy_from_slice(&8u32.to_le_bytes());
        bytes[0x6C..0x70].copy_from_slice(&8u32.to_le_bytes());
        bytes[0x8C..0x90].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x94..0x98].copy_from_slice(&2u32.to_le_bytes());
        let mut object = Object { paddr: 2, bytes };
        validate_checkpoint_bounds(&object).unwrap();

        object.bytes[0x68..0x6C].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint descriptor ring size",
                observed: 2,
            })
        );
        object.bytes[0x68..0x6C].copy_from_slice(&8u32.to_le_bytes());

        object.bytes[0x6C..0x70].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint data ring size",
                observed: 1,
            })
        );
        object.bytes[0x6C..0x70].copy_from_slice(&8u32.to_le_bytes());

        object.bytes[0x8C..0x90].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint descriptor segment length",
                observed: 1,
            })
        );
        object.bytes[0x8C..0x90].copy_from_slice(&2u32.to_le_bytes());

        object.bytes[0x94..0x98].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint data segment length",
                observed: 1,
            })
        );
        object.bytes[0x94..0x98].copy_from_slice(&2u32.to_le_bytes());

        object.bytes[0x88..0x8C].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint area index",
                observed: 8,
            })
        );
        object.bytes[0x88..0x8C].copy_from_slice(&7u32.to_le_bytes());
        validate_checkpoint_bounds(&object).expect("checkpoint descriptor ring may wrap");
        object.bytes[0x88..0x8C].copy_from_slice(&0u32.to_le_bytes());

        object.bytes[0x80..0x84].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint descriptor ring cursor",
                observed: 8,
            })
        );
        object.bytes[0x80..0x84].copy_from_slice(&0u32.to_le_bytes());
        object.bytes[0x84..0x88].copy_from_slice(&8u32.to_le_bytes());
        assert_eq!(
            validate_checkpoint_bounds(&object),
            Err(VerifyError::FieldOutOfRange {
                what: "checkpoint data ring cursor",
                observed: 8,
            })
        );
    }

    #[test]
    fn a_stale_checkpoint_is_not_preferred_over_a_newer_one() {
        let Some(mut capture) = Capture::apple() else {
            eprintln!("skipped: {} is not present", apple_capture_path());
            return;
        };
        let before = capture.verify().expect("verify");

        let descriptor_base = u64_at(capture.block(0), 0x70);
        let descriptor_blocks = u32_at(capture.block(0), 0x68) as u64;
        let older: Vec<u64> = (descriptor_base..descriptor_base + descriptor_blocks)
            .filter(|paddr| {
                let block = capture.block(*paddr);
                u32_at(block, 0x18) & OBJ_TYPE_MASK == TYPE_NX_SUPERBLOCK
                    && u32_at(block, 0x20) == NX_MAGIC
                    && u64_at(block, 0x10) < before.xid
            })
            .collect();
        assert_eq!(
            older.len(),
            3,
            "the capture must carry older checkpoints for this to mean anything"
        );

        capture.edit(0, |block| {
            block[0x10..0x18].copy_from_slice(&0u64.to_le_bytes())
        });

        let after = capture.verify().expect("verify after ageing block zero");
        assert_eq!(after.xid, before.xid);
        assert_eq!(after.superblock_paddr, before.superblock_paddr);
        assert_ne!(after.superblock_paddr, 0);
        assert_eq!(after.volumes.len(), before.volumes.len());
    }
}
