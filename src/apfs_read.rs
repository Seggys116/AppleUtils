use std::fmt;
use std::io::Write;

use crate::apfs_verify::{
    APFS_INCOMPAT_SEALED_VOLUME, APFS_MAGIC, BlockSource, DrecKeyLayout, J_CRYPTO_STATE, J_DIR_REC,
    J_FILE_EXTENT, J_INODE, J_XATTR, MAX_REASONABLE_BLOCKS, NX_MAGIC, OBJ_PHYSICAL,
    OBJ_STORAGE_MASK, OBJ_TYPE_MASK, OBJ_VIRTUAL, OmapEntry, ROOT_DIR_INO_NUM,
    ROOT_SNAPSHOT_PREFIX, SliceBlocks, TYPE_BTREE, TYPE_BTREE_NODE, TYPE_FS, TYPE_NX_SUPERBLOCK,
    Verifier, VerifyError, checksum_valid, resolve, u16_at, u32_at, u64_at,
};
use crate::apfs_verify::{BTreeNode, Object, SnapshotRecord};
use crate::asr_server::deflate::adler32;
use crate::lzvn::{self, LzvnError};

const PROBE_BYTES: usize = 4096;

const NXSB_BLOCK_SIZE_OFFSET: usize = 0x24;
const NXSB_BLOCK_COUNT_OFFSET: usize = 0x28;
const NXSB_XP_DESC_BLOCKS_OFFSET: usize = 0x68;
const NXSB_XP_DESC_BASE_OFFSET: usize = 0x70;
const NXSB_OMAP_OID_OFFSET: usize = 0xA0;
const NXSB_MAX_FILE_SYSTEMS_OFFSET: usize = 0xB4;
const NXSB_FS_OID_OFFSET: usize = 0xB8;

const APSB_INCOMPATIBLE_FEATURES_OFFSET: usize = 0x38;
const APSB_OMAP_OID_OFFSET: usize = 0x80;
const APSB_ROOT_TREE_OID_OFFSET: usize = 0x88;
const APSB_SNAP_META_TREE_OID_OFFSET: usize = 0x98;
const APSB_NUM_SNAPSHOTS_OFFSET: usize = 0xD8;
const APSB_VOL_UUID_OFFSET: usize = 0xF0;
const APSB_VOL_UUID_BYTES: usize = 16;
const APSB_FS_FLAGS_OFFSET: usize = 0x108;
const APSB_VOLNAME_OFFSET: usize = 0x2C0;
const APSB_VOLNAME_BYTES: usize = 256;
const APSB_ROLE_OFFSET: usize = 0x3C4;
const APSB_VOLUME_GROUP_ID_OFFSET: usize = 0x3F0;
const APSB_FEXT_TREE_OID_OFFSET: usize = 0x408;
const APSB_FEXT_TREE_TYPE_OFFSET: usize = 0x410;

const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;

const TYPE_FEXT_TREE: u32 = 0x1F;

const J_OBJ_ID_MASK: u64 = 0x0FFF_FFFF_FFFF_FFFF;
const J_KIND_SHIFT: u32 = 60;

const DREC_FILE_ID_OFFSET: usize = 0x00;
const DREC_FLAGS_OFFSET: usize = 0x10;
const DREC_VALUE_BYTES: usize = 0x12;
const DREC_TYPE_MASK: u16 = 0x000F;
pub const DT_DIR: u16 = 4;
pub const DT_REG: u16 = 8;
pub const DT_LNK: u16 = 10;

const INODE_PRIVATE_ID_OFFSET: usize = 0x08;
const INODE_BSD_FLAGS_OFFSET: usize = 0x44;
const INODE_MODE_OFFSET: usize = 0x50;
const INODE_XFIELDS_OFFSET: usize = 0x5C;

pub const S_IFMT: u16 = 0xF000;
pub const S_IFREG: u16 = 0x8000;
pub const S_IFDIR: u16 = 0x4000;
pub const S_IFLNK: u16 = 0xA000;

const UF_COMPRESSED: u32 = 0x0000_0020;

const XFIELD_BLOB_HEADER_BYTES: usize = 4;
const XFIELD_ENTRY_BYTES: usize = 4;
const XFIELD_DATA_ALIGNMENT: usize = 8;

const INO_EXT_TYPE_DSTREAM: u8 = 8;

const DSTREAM_BYTES: usize = 40;
const DSTREAM_SIZE_OFFSET: usize = 0x00;
const DSTREAM_DEFAULT_CRYPTO_ID_OFFSET: usize = 0x10;

const XATTR_NAME_LENGTH_OFFSET: usize = 0x08;
const XATTR_NAME_OFFSET: usize = 0x0A;
const XATTR_FLAGS_OFFSET: usize = 0x00;
const XATTR_DATA_LENGTH_OFFSET: usize = 0x02;
const XATTR_DATA_OFFSET: usize = 0x04;

const XATTR_DATA_STREAM: u16 = 0x0001;
const XATTR_DATA_EMBEDDED: u16 = 0x0002;

const XATTR_DSTREAM_BYTES: usize = 8 + DSTREAM_BYTES;

const EXTENT_LOGICAL_OFFSET: usize = 0x08;
const EXTENT_KEY_BYTES: usize = 0x10;
const EXTENT_LENGTH_OFFSET: usize = 0x00;
const EXTENT_PHYSICAL_OFFSET: usize = 0x08;
const EXTENT_VALUE_BYTES: usize = 0x10;
const EXTENT_CRYPTO_ID_OFFSET: usize = 0x10;
const EXTENT_VALUE_WITH_CRYPTO_BYTES: usize = 0x18;

const CRYPTO_REFCNT_OFFSET: usize = 0x00;
const CRYPTO_MAJOR_VERSION_OFFSET: usize = 0x04;
const CRYPTO_MINOR_VERSION_OFFSET: usize = 0x06;
const CRYPTO_FLAGS_OFFSET: usize = 0x08;
const CRYPTO_PERSISTENT_CLASS_OFFSET: usize = 0x0C;
const CRYPTO_KEY_OS_VERSION_OFFSET: usize = 0x10;
const CRYPTO_KEY_REVISION_OFFSET: usize = 0x14;
const CRYPTO_KEY_LEN_OFFSET: usize = 0x16;
const CRYPTO_PERSISTENT_KEY_OFFSET: usize = 0x18;
const EXTENT_LENGTH_MASK: u64 = 0x00FF_FFFF_FFFF_FFFF;

// A sealed volume keys its extents on the inode's private_id in a physical fext tree, so a catalog search for them finds nothing.
const FEXT_KEY_BYTES: usize = 0x10;
const FEXT_PRIVATE_ID_OFFSET: usize = 0x00;
const FEXT_LOGICAL_OFFSET: usize = 0x08;
const FEXT_VALUE_BYTES: usize = 0x10;
const FEXT_LENGTH_OFFSET: usize = 0x00;
const FEXT_PHYSICAL_OFFSET: usize = 0x08;

const DECMPFS_XATTR_NAME: &str = "com.apple.decmpfs";
const RESOURCE_FORK_XATTR_NAME: &str = "com.apple.ResourceFork";

const DECMPFS_MAGIC: u32 = 0x636D_7066;
const DECMPFS_HEADER_BYTES: usize = 16;
const DECMPFS_TYPE_OFFSET: usize = 0x04;
const DECMPFS_SIZE_OFFSET: usize = 0x08;

const DECMPFS_TYPE_INLINE_RAW: u32 = 1;
const DECMPFS_TYPE_INLINE_ZLIB: u32 = 3;
const DECMPFS_TYPE_RESOURCE_ZLIB: u32 = 4;
const DECMPFS_TYPE_INLINE_LZVN: u32 = 7;
const DECMPFS_TYPE_RESOURCE_LZVN: u32 = 8;

const DECMPFS_BLOCK_STORED_MARKER: u8 = 0x0F;

const DECMPFS_LZVN_STORED_MARKER: u8 = 0x06;

const DECMPFS_BLOCK_BYTES: usize = 0x1_0000;

const RSRC_HEADER_BYTES: usize = 16;
const RSRC_DATA_OFFSET_OFFSET: usize = 0x00;
const RSRC_DATA_LENGTH_OFFSET: usize = 0x08;

const RSRC_ENTRY_LENGTH_BYTES: usize = 4;
const RSRC_BLOCK_ENTRY_BYTES: usize = 8;

const LZVN_TABLE_ENTRY_BYTES: usize = 4;

const MAX_PATH_COMPONENTS: usize = 256;

const MAX_TREE_NODES: usize = 1 << 16;

const MAX_RECORDS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApfsReadError {
    ImageTooSmall {
        length: usize,
        needed: usize,
    },
    NotAContainer {
        observed: u32,
    },
    UnsupportedBlockSize {
        block_size: u32,
    },
    ImplausibleBlockCount {
        block_count: u64,
    },
    ImageShorterThanContainer {
        image_bytes: u64,
        container_bytes: u64,
    },
    CheckpointDescriptorUnusable {
        first: u64,
        count: u64,
    },
    NoCheckpoint {
        first: u64,
        count: u64,
    },
    GeometryMismatch {
        paddr: u64,
        expected_block_size: u32,
        expected_block_count: u64,
        observed_block_size: u32,
        observed_block_count: u64,
    },
    ImplausibleVolumeSlots {
        max_file_systems: u32,
    },
    NotAVolume {
        paddr: u64,
        observed: u32,
    },
    VolumeNotVirtual {
        paddr: u64,
        storage: u32,
    },
    NoVolumes,
    NoWalkableVolume {
        path: String,
        sealed: usize,
    },
    Container {
        what: &'static str,
        source: VerifyError,
    },
    PathNotAbsolute {
        path: String,
    },
    PathNamesNoFile {
        path: String,
    },
    PathLeavesRoot {
        path: String,
    },
    PathTooDeep {
        path: String,
        components: usize,
    },
    ComponentNotFound {
        path: String,
        component: String,
        parent_id: u64,
        volume: String,
    },
    NotADirectory {
        path: String,
        component: String,
        dirent_type: u16,
    },
    NoInode {
        path: String,
        file_id: u64,
    },
    NotARegularFile {
        path: String,
        file_id: u64,
        mode: u16,
    },
    NotASymlink {
        path: String,
        file_id: u64,
        mode: u16,
    },
    RecordMalformed {
        path: String,
        object_id: u64,
        kind: u64,
        reason: &'static str,
    },
    TooManyRecords {
        object_id: u64,
        kind: u64,
        limit: usize,
    },
    TreeWalkTooLong {
        paddr: u64,
        limit: usize,
    },
    TreeLevelMismatch {
        paddr: u64,
        expected: u16,
        observed: u16,
    },
    NoDataStream {
        path: String,
        file_id: u64,
        extents: usize,
    },
    MissingExtents {
        path: String,
        object_id: u64,
        size: u64,
    },
    SizeOverflow {
        path: String,
        object_id: u64,
        size: u64,
        limit: u64,
    },
    CompressionHeaderMissing {
        path: String,
        file_id: u64,
    },
    CompressionHeaderTruncated {
        path: String,
        file_id: u64,
        length: usize,
    },
    CompressionHeaderBadMagic {
        path: String,
        file_id: u64,
        observed: u32,
    },
    UnsupportedCompression {
        path: String,
        file_id: u64,
        compression_type: u32,
    },
    ResourceForkMissing {
        path: String,
        file_id: u64,
    },
    ResourceForkMalformed {
        path: String,
        file_id: u64,
        reason: &'static str,
    },
    CompressedStreamBroken {
        path: String,
        file_id: u64,
        block: usize,
        source: InflateError,
    },
    LzvnStreamBroken {
        path: String,
        file_id: u64,
        block: usize,
        source: LzvnError,
    },
    CompressedSizeMismatch {
        path: String,
        file_id: u64,
        declared: u64,
        produced: usize,
    },
    UnsupportedXattrStorage {
        path: String,
        file_id: u64,
        name: &'static str,
        flags: u16,
    },
    VolumeNotSelected {
        wanted: String,
        available: Vec<String>,
    },
    VolumeAmbiguous {
        wanted: String,
        matched: Vec<String>,
    },
    VolumeEncrypted {
        volume: String,
        fs_flags: u64,
    },
    SealedWithoutExtentTree {
        volume: String,
    },
    SnapshotNotFound {
        volume: String,
        wanted: String,
        available: Vec<String>,
    },
    NoRootSnapshot {
        volume: String,
    },
    SnapshotWithoutSuperblock {
        volume: String,
        snapshot: String,
    },
    NotADirectoryToList {
        path: String,
        file_id: u64,
        mode: u16,
    },
    RangeStartsPastEnd {
        path: String,
        start: u64,
        size: u64,
    },
    CompressedTooLargeToBuffer {
        path: String,
        file_id: u64,
        size: u64,
        limit: u64,
    },
    Output {
        what: &'static str,
        reason: String,
    },
}

impl fmt::Display for ApfsReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageTooSmall { length, needed } => write!(
                f,
                "the image is {length} bytes, too short for the {needed} bytes a container \
                 superblock probe reads"
            ),
            Self::NotAContainer { observed } => write!(
                f,
                "block zero has magic {observed:#010x} at offset 0x20, not the NXSB of a container \
                 superblock"
            ),
            Self::UnsupportedBlockSize { block_size } => {
                write!(
                    f,
                    "the container names block size {block_size}, which is not a power of two between 512 and 65536"
                )
            }
            Self::ImplausibleBlockCount { block_count } => write!(
                f,
                "the container names {block_count} blocks, outside the 1 to {MAX_REASONABLE_BLOCKS} a container holds"
            ),
            Self::ImageShorterThanContainer {
                image_bytes,
                container_bytes,
            } => write!(
                f,
                "the image is {image_bytes} bytes but the container superblock describes \
                 {container_bytes}"
            ),
            Self::CheckpointDescriptorUnusable { first, count } => write!(
                f,
                "the checkpoint descriptor area of {count} blocks at {first} is empty or leaves \
                 the container"
            ),
            Self::NoCheckpoint { first, count } => write!(
                f,
                "none of the {count} blocks at {first} in the checkpoint descriptor area holds a \
                 container superblock"
            ),
            Self::GeometryMismatch {
                paddr,
                expected_block_size,
                expected_block_count,
                observed_block_size,
                observed_block_count,
            } => write!(
                f,
                "the checkpoint superblock at block {paddr} describes {observed_block_count} \
                 blocks of {observed_block_size} bytes, but block zero describes \
                 {expected_block_count} of {expected_block_size}"
            ),
            Self::ImplausibleVolumeSlots { max_file_systems } => write!(
                f,
                "the container names {max_file_systems} volume slots, outside the 1 to 100 a \
                 container holds"
            ),
            Self::NotAVolume { paddr, observed } => write!(
                f,
                "the volume superblock at block {paddr} has magic {observed:#010x} at offset 0x20, \
                 not the APFS of a volume superblock"
            ),
            Self::VolumeNotVirtual { paddr, storage } => write!(
                f,
                "the volume superblock at block {paddr} is in storage class {storage:#010x}, not \
                 the virtual class a volume superblock is in"
            ),
            Self::NoVolumes => {
                f.write_str("the container superblock names no volumes to look a path up in")
            }
            Self::NoWalkableVolume { path, sealed } => write!(
                f,
                "no volume in the container could be walked for {path}: {sealed} of them are \
                 sealed, and a sealed volume's filesystem tree is hashed and headerless"
            ),
            Self::Container { what, source } => write!(f, "reading {what}: {source}"),
            Self::PathNotAbsolute { path } => {
                write!(f, "the path {path} does not start at the root")
            }
            Self::PathNamesNoFile { path } => {
                write!(f, "the path {path} names a root, not a file inside it")
            }
            Self::PathLeavesRoot { path } => write!(
                f,
                "the path {path} walks upwards through a parent component, which this reader does \
                 not follow"
            ),
            Self::PathTooDeep { path, components } => write!(
                f,
                "the path {path} has {components} components, more than the {MAX_PATH_COMPONENTS} \
                 this reader follows"
            ),
            Self::ComponentNotFound {
                path,
                component,
                parent_id,
                volume,
            } => write!(
                f,
                "looking up {path} on volume {volume}: directory {parent_id} holds no entry named \
                 {component}"
            ),
            Self::NotADirectory {
                path,
                component,
                dirent_type,
            } => write!(
                f,
                "looking up {path}: the component {component} is directory entry type \
                 {dirent_type}, not a directory"
            ),
            Self::NoInode { path, file_id } => write!(
                f,
                "{path} resolved to file id {file_id}, which has no inode record"
            ),
            Self::NotARegularFile {
                path,
                file_id,
                mode,
            } => write!(
                f,
                "{path} is file id {file_id} with mode {mode:#o}, not a regular file"
            ),
            Self::NotASymlink {
                path,
                file_id,
                mode,
            } => write!(
                f,
                "{path} is file id {file_id} with mode {mode:#o}, not a symlink"
            ),
            Self::RecordMalformed {
                path,
                object_id,
                kind,
                reason,
            } => write!(
                f,
                "reading {path}: a kind {kind} record for object {object_id} is malformed: {reason}"
            ),
            Self::TooManyRecords {
                object_id,
                kind,
                limit,
            } => write!(
                f,
                "object {object_id} has more than {limit} records of kind {kind}"
            ),
            Self::TreeWalkTooLong { paddr, limit } => write!(
                f,
                "the filesystem tree search reached block {paddr} after {limit} nodes, so the tree \
                 is cyclic or far deeper than a filesystem tree is"
            ),
            Self::TreeLevelMismatch {
                paddr,
                expected,
                observed,
            } => write!(
                f,
                "the filesystem tree node at block {paddr} is at level {observed}, but its parent \
                 puts it at {expected}"
            ),
            Self::NoDataStream {
                path,
                file_id,
                extents,
            } => write!(
                f,
                "{path} is file id {file_id} with no data stream extended field, yet the volume \
                 holds {extents} extents for it, so its length cannot be established"
            ),
            Self::MissingExtents {
                path,
                object_id,
                size,
            } => write!(
                f,
                "reading {path}: object {object_id} names a {size}-byte stream that no file extent \
                 record covers"
            ),
            Self::SizeOverflow {
                path,
                object_id,
                size,
                limit,
            } => write!(
                f,
                "reading {path}: object {object_id} names a {size}-byte stream, longer than the \
                 {limit}-byte container that holds it"
            ),
            Self::CompressionHeaderMissing { path, file_id } => write!(
                f,
                "{path} is file id {file_id} marked compressed, but carries no \
                 {DECMPFS_XATTR_NAME} attribute to decompress from"
            ),
            Self::CompressionHeaderTruncated {
                path,
                file_id,
                length,
            } => write!(
                f,
                "the {DECMPFS_XATTR_NAME} attribute of {path}, file id {file_id}, is {length} \
                 bytes, shorter than its {DECMPFS_HEADER_BYTES}-byte header"
            ),
            Self::CompressionHeaderBadMagic {
                path,
                file_id,
                observed,
            } => write!(
                f,
                "the {DECMPFS_XATTR_NAME} attribute of {path}, file id {file_id}, starts with \
                 {observed:#010x}, not the fpmc of a compression header"
            ),
            Self::UnsupportedCompression {
                path,
                file_id,
                compression_type,
            } => write!(
                f,
                "{path} is file id {file_id} compressed with decmpfs type {compression_type}, \
                 which this reader does not decode"
            ),
            Self::ResourceForkMissing { path, file_id } => write!(
                f,
                "{path} is file id {file_id} compressed into its resource fork, but carries no \
                 {RESOURCE_FORK_XATTR_NAME} attribute"
            ),
            Self::ResourceForkMalformed {
                path,
                file_id,
                reason,
            } => write!(
                f,
                "the resource fork of {path}, file id {file_id}, is malformed: {reason}"
            ),
            Self::CompressedStreamBroken {
                path,
                file_id,
                block,
                source,
            } => write!(
                f,
                "compressed block {block} of {path}, file id {file_id}, did not decode: {source}"
            ),
            Self::LzvnStreamBroken {
                path,
                file_id,
                block,
                source,
            } => write!(
                f,
                "LZVN block {block} of {path}, file id {file_id}, did not decode: {source}"
            ),
            Self::CompressedSizeMismatch {
                path,
                file_id,
                declared,
                produced,
            } => write!(
                f,
                "{path}, file id {file_id}, declares {declared} uncompressed bytes but decoded to \
                 {produced}"
            ),
            Self::UnsupportedXattrStorage {
                path,
                file_id,
                name,
                flags,
            } => write!(
                f,
                "the {name} attribute of {path}, file id {file_id}, has storage flags \
                 {flags:#06x}, which is neither embedded nor a data stream"
            ),
            Self::VolumeNotSelected { wanted, available } => write!(
                f,
                "no volume in the container is {wanted}; it holds {}",
                describe_list(available)
            ),
            Self::VolumeAmbiguous { wanted, matched } => write!(
                f,
                "{} volumes are {wanted}, so which was meant cannot be established: {}",
                matched.len(),
                describe_list(matched)
            ),
            Self::VolumeEncrypted { volume, fs_flags } => write!(
                f,
                "volume {volume:?} has apfs_fs_flags {fs_flags:#x}, which does not carry \
                 APFS_FS_UNENCRYPTED, so its file contents are wrapped in a volume key this \
                 read was given no way to establish. Name the VM bundle that wrote the disc and \
                 the key is recovered from the container keybag under that VM's own derivation: \
                 --encrypted-extents unwrap --vm-bundle <dir>. A bundle whose identity did not \
                 mint this volume's key is refused there too"
            ),
            Self::SealedWithoutExtentTree { volume } => write!(
                f,
                "volume {volume:?} is sealed but names no apfs_fext_tree_oid, so its file \
                 extents are in neither the catalog nor an extent tree"
            ),
            Self::SnapshotNotFound {
                volume,
                wanted,
                available,
            } => write!(
                f,
                "volume {volume:?} records no snapshot named {wanted:?}; it records {}",
                describe_list(available)
            ),
            Self::NoRootSnapshot { volume } => write!(
                f,
                "volume {volume:?} records no {ROOT_SNAPSHOT_PREFIX}* root snapshot"
            ),
            Self::SnapshotWithoutSuperblock { volume, snapshot } => write!(
                f,
                "snapshot {snapshot:?} of volume {volume:?} names no preserved volume \
                 superblock, so the state it stands for cannot be mounted"
            ),
            Self::NotADirectoryToList {
                path,
                file_id,
                mode,
            } => write!(
                f,
                "{path}, file id {file_id}, has mode {mode:#06x}, which is not a directory to list"
            ),
            Self::RangeStartsPastEnd { path, start, size } => write!(
                f,
                "the range asked for starts at byte {start} of {path}, which is {size} bytes long"
            ),
            Self::CompressedTooLargeToBuffer {
                path,
                file_id,
                size,
                limit,
            } => write!(
                f,
                "{path}, file id {file_id}, is compressed and decodes to {size} bytes, which is \
                 past the {limit} bytes this reader will hold to decode one whole"
            ),
            Self::Output { what, reason } => {
                write!(f, "writing {what} out failed: {reason}")
            }
        }
    }
}

impl std::error::Error for ApfsReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Container { source, .. } => Some(source),
            Self::CompressedStreamBroken { source, .. } => Some(source),
            Self::LzvnStreamBroken { source, .. } => Some(source),
            _ => None,
        }
    }
}

fn faulted(what: &'static str) -> impl Fn(VerifyError) -> ApfsReadError {
    move |source| ApfsReadError::Container { what, source }
}

pub fn read_file_from_container(image: &[u8], path: &str) -> Result<Vec<u8>, ApfsReadError> {
    let components = path_components(path)?;
    let (block_size, block_count) = container_geometry(image)?;
    let mut blocks = SliceBlocks::new(image, block_size);
    let mut reader = Reader::mount(&mut blocks, block_size, block_count)?;
    reader.read_path(path, &components)
}

fn path_components(path: &str) -> Result<Vec<&str>, ApfsReadError> {
    if !path.starts_with('/') {
        return Err(ApfsReadError::PathNotAbsolute {
            path: path.to_string(),
        });
    }
    let components: Vec<&str> = path
        .split('/')
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.contains(&"..") {
        return Err(ApfsReadError::PathLeavesRoot {
            path: path.to_string(),
        });
    }
    if components.is_empty() {
        return Err(ApfsReadError::PathNamesNoFile {
            path: path.to_string(),
        });
    }
    if components.len() > MAX_PATH_COMPONENTS {
        return Err(ApfsReadError::PathTooDeep {
            path: path.to_string(),
            components: components.len(),
        });
    }
    Ok(components)
}

fn container_geometry(image: &[u8]) -> Result<(u32, u64), ApfsReadError> {
    if image.len() < PROBE_BYTES {
        return Err(ApfsReadError::ImageTooSmall {
            length: image.len(),
            needed: PROBE_BYTES,
        });
    }
    let (block_size, block_count) = container_geometry_of(image)?;
    let container_bytes = block_count
        .checked_mul(u64::from(block_size))
        .ok_or(ApfsReadError::ImplausibleBlockCount { block_count })?;
    if (image.len() as u64) < container_bytes {
        return Err(ApfsReadError::ImageShorterThanContainer {
            image_bytes: image.len() as u64,
            container_bytes,
        });
    }
    Ok((block_size, block_count))
}

pub fn container_geometry_of(block_zero: &[u8]) -> Result<(u32, u64), ApfsReadError> {
    if block_zero.len() < NXSB_BLOCK_COUNT_OFFSET + 8 {
        return Err(ApfsReadError::ImageTooSmall {
            length: block_zero.len(),
            needed: NXSB_BLOCK_COUNT_OFFSET + 8,
        });
    }
    let magic = u32_at(block_zero, 0x20);
    if magic != NX_MAGIC {
        return Err(ApfsReadError::NotAContainer { observed: magic });
    }
    let block_size = u32_at(block_zero, NXSB_BLOCK_SIZE_OFFSET);
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(ApfsReadError::UnsupportedBlockSize { block_size });
    }
    let block_count = u64_at(block_zero, NXSB_BLOCK_COUNT_OFFSET);
    if block_count == 0 || block_count > MAX_REASONABLE_BLOCKS {
        return Err(ApfsReadError::ImplausibleBlockCount { block_count });
    }
    Ok((block_size, block_count))
}

struct Reader<'a> {
    verifier: Verifier<'a>,
    xid: u64,
    container_omap: Vec<OmapEntry>,
    volume_oids: Vec<u64>,
    superblock_paddr: u64,
    container_bytes: u64,
}

struct Volume {
    oid: u64,
    name: String,
    role: u16,
    sealed: bool,
    encrypted: bool,
    fs_flags: u64,
    uuid: [u8; APSB_VOL_UUID_BYTES],
    volume_group_id: [u8; 16],
    incompatible_features: u64,
    layout: DrecKeyLayout,
    fs_tree_oid: u64,
    fs_tree_paddr: u64,
    apsb_paddr: u64,
    omap: Vec<OmapEntry>,
    resolve_xid: u64,
    snap_meta_tree_paddr: u64,
    declared_snapshots: u64,
    extents: ExtentSource,
    headerless_catalog: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtentSource {
    Catalog,
    FextTree { paddr: u64 },
}

impl<'a> Reader<'a> {
    fn mount(
        source: &'a mut dyn BlockSource,
        block_size: u32,
        block_count: u64,
    ) -> Result<Self, ApfsReadError> {
        let mut verifier = Verifier {
            source,
            block_size: block_size as usize,
            block_count,
            objects_checked: 0,
            in_use: Vec::new(),
        };

        let zero = verifier
            .read_checked(0)
            .map_err(faulted("the container superblock copy in block zero"))?;
        let descriptor_base = u64_at(&zero.bytes, NXSB_XP_DESC_BASE_OFFSET);
        let descriptor_blocks = u64::from(u32_at(&zero.bytes, NXSB_XP_DESC_BLOCKS_OFFSET));
        let descriptor_end = descriptor_base.checked_add(descriptor_blocks);
        if descriptor_blocks == 0 || descriptor_end.is_none_or(|end| end > block_count) {
            return Err(ApfsReadError::CheckpointDescriptorUnusable {
                first: descriptor_base,
                count: descriptor_blocks,
            });
        }

        let mut best: Option<(u64, u64)> = None;
        let mut bytes = vec![0u8; block_size as usize];
        for slot in 0..descriptor_blocks {
            let paddr = descriptor_base + slot;
            verifier
                .source
                .read_block(paddr, &mut bytes)
                .map_err(faulted("the checkpoint descriptor area"))?;
            if !checksum_valid(&bytes) {
                continue;
            }
            if u32_at(&bytes, 0x18) & OBJ_TYPE_MASK != TYPE_NX_SUPERBLOCK {
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
        let (xid, superblock_paddr) = best.ok_or(ApfsReadError::NoCheckpoint {
            first: descriptor_base,
            count: descriptor_blocks,
        })?;

        let superblock = verifier
            .read_checked(superblock_paddr)
            .map_err(faulted("the checkpoint's container superblock"))?;
        let sb = superblock.bytes;
        let observed_block_count = u64_at(&sb, NXSB_BLOCK_COUNT_OFFSET);
        let observed_block_size = u32_at(&sb, NXSB_BLOCK_SIZE_OFFSET);
        if observed_block_count != block_count || observed_block_size != block_size {
            return Err(ApfsReadError::GeometryMismatch {
                paddr: superblock_paddr,
                expected_block_size: block_size,
                expected_block_count: block_count,
                observed_block_size,
                observed_block_count,
            });
        }

        let omap_tree = verifier
            .read_omap(u64_at(&sb, NXSB_OMAP_OID_OFFSET), "container object map")
            .map_err(faulted("the container object map"))?;
        let container_omap = verifier
            .collect_omap(omap_tree, "container object map tree")
            .map_err(faulted("the container object map tree"))?;

        let max_file_systems = u32_at(&sb, NXSB_MAX_FILE_SYSTEMS_OFFSET);
        if max_file_systems == 0 || max_file_systems > 100 {
            return Err(ApfsReadError::ImplausibleVolumeSlots { max_file_systems });
        }
        let volume_oids: Vec<u64> = (0..max_file_systems as usize)
            .map(|index| u64_at(&sb, NXSB_FS_OID_OFFSET + index * 8))
            .filter(|oid| *oid != 0)
            .collect();

        Ok(Self {
            verifier,
            xid,
            container_omap,
            volume_oids,
            superblock_paddr,
            container_bytes: block_count * u64::from(block_size),
        })
    }

    fn read_path(&mut self, path: &str, components: &[&str]) -> Result<Vec<u8>, ApfsReadError> {
        if self.volume_oids.is_empty() {
            return Err(ApfsReadError::NoVolumes);
        }
        let mut sealed = 0usize;
        let mut first_miss: Option<ApfsReadError> = None;
        for oid in self.volume_oids.clone() {
            let volume = self.open_volume(oid)?;
            if volume.sealed {
                sealed += 1;
                continue;
            }
            match self.read_from_volume(&volume, path, components) {
                Ok(bytes) => return Ok(bytes),
                Err(missing @ ApfsReadError::ComponentNotFound { .. }) => {
                    first_miss.get_or_insert(missing);
                }
                Err(other) => return Err(other),
            }
        }
        Err(first_miss.unwrap_or(ApfsReadError::NoWalkableVolume {
            path: path.to_string(),
            sealed,
        }))
    }

    fn open_volume(&mut self, oid: u64) -> Result<Volume, ApfsReadError> {
        let paddr = resolve(&self.container_omap, oid, self.xid)
            .map_err(faulted("a volume superblock's object map entry"))?;
        let volume: Object = self
            .verifier
            .read_expecting(paddr, Some(oid), TYPE_FS, "volume superblock")
            .map_err(faulted("a volume superblock"))?;
        if volume.storage() != OBJ_VIRTUAL {
            return Err(ApfsReadError::VolumeNotVirtual {
                paddr,
                storage: volume.storage(),
            });
        }
        self.decode_volume(volume.bytes, paddr, oid, self.xid)
    }

    fn decode_volume(
        &mut self,
        bytes: Vec<u8>,
        paddr: u64,
        oid: u64,
        resolve_xid: u64,
    ) -> Result<Volume, ApfsReadError> {
        let magic = u32_at(&bytes, 0x20);
        if magic != APFS_MAGIC {
            return Err(ApfsReadError::NotAVolume {
                paddr,
                observed: magic,
            });
        }

        let incompatible_features = u64_at(&bytes, APSB_INCOMPATIBLE_FEATURES_OFFSET);
        let omap_tree = self
            .verifier
            .read_omap(u64_at(&bytes, APSB_OMAP_OID_OFFSET), "volume object map")
            .map_err(faulted("a volume object map"))?;
        let omap = self
            .verifier
            .collect_omap(omap_tree, "volume object map tree")
            .map_err(faulted("a volume object map tree"))?;
        let fs_tree_oid = u64_at(&bytes, APSB_ROOT_TREE_OID_OFFSET);
        let fs_tree_paddr = resolve(&omap, fs_tree_oid, resolve_xid)
            .map_err(faulted("a volume's filesystem tree root"))?;

        let name_end = bytes[APSB_VOLNAME_OFFSET..APSB_VOLNAME_OFFSET + APSB_VOLNAME_BYTES]
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(0);
        let name =
            String::from_utf8_lossy(&bytes[APSB_VOLNAME_OFFSET..APSB_VOLNAME_OFFSET + name_end])
                .into_owned();

        let sealed = incompatible_features & APFS_INCOMPAT_SEALED_VOLUME != 0;
        let fext_tree_oid = u64_at(&bytes, APSB_FEXT_TREE_OID_OFFSET);
        let fext_tree_type = u32_at(&bytes, APSB_FEXT_TREE_TYPE_OFFSET);
        let extents = self.extent_source(
            &name,
            sealed,
            fext_tree_oid,
            fext_tree_type,
            &omap,
            resolve_xid,
        )?;

        let fs_flags = u64_at(&bytes, APSB_FS_FLAGS_OFFSET);
        let mut uuid = [0u8; APSB_VOL_UUID_BYTES];
        uuid.copy_from_slice(
            &bytes[APSB_VOL_UUID_OFFSET..APSB_VOL_UUID_OFFSET + APSB_VOL_UUID_BYTES],
        );
        let mut volume_group_id = [0u8; 16];
        if bytes.len() >= APSB_VOLUME_GROUP_ID_OFFSET + 16 {
            volume_group_id.copy_from_slice(
                &bytes[APSB_VOLUME_GROUP_ID_OFFSET..APSB_VOLUME_GROUP_ID_OFFSET + 16],
            );
        }

        Ok(Volume {
            oid,
            name,
            role: u16_at(&bytes, APSB_ROLE_OFFSET),
            sealed,
            encrypted: fs_flags & APFS_FS_UNENCRYPTED == 0,
            fs_flags,
            uuid,
            volume_group_id,
            incompatible_features,
            layout: DrecKeyLayout::of(incompatible_features),
            fs_tree_oid,
            fs_tree_paddr,
            apsb_paddr: paddr,
            omap,
            resolve_xid,
            snap_meta_tree_paddr: u64_at(&bytes, APSB_SNAP_META_TREE_OID_OFFSET),
            declared_snapshots: u64_at(&bytes, APSB_NUM_SNAPSHOTS_OFFSET),
            extents,
            headerless_catalog: sealed,
        })
    }

    fn extent_source(
        &mut self,
        volume: &str,
        sealed: bool,
        fext_tree_oid: u64,
        fext_tree_type: u32,
        omap: &[OmapEntry],
        resolve_xid: u64,
    ) -> Result<ExtentSource, ApfsReadError> {
        if !sealed {
            return Ok(ExtentSource::Catalog);
        }
        if fext_tree_oid == 0 {
            return Err(ApfsReadError::SealedWithoutExtentTree {
                volume: volume.to_string(),
            });
        }
        let paddr = if fext_tree_type & OBJ_STORAGE_MASK == OBJ_PHYSICAL {
            fext_tree_oid
        } else {
            resolve(omap, fext_tree_oid, resolve_xid)
                .map_err(faulted("a sealed volume's file extent tree root"))?
        };
        Ok(ExtentSource::FextTree { paddr })
    }

    fn read_from_volume(
        &mut self,
        volume: &Volume,
        path: &str,
        components: &[&str],
    ) -> Result<Vec<u8>, ApfsReadError> {
        let mut current = ROOT_DIR_INO_NUM;
        for (index, component) in components.iter().enumerate() {
            let (file_id, dirent_type) = self.lookup(volume, current, component, path)?;
            if index + 1 < components.len() && dirent_type != DT_DIR {
                return Err(ApfsReadError::NotADirectory {
                    path: path.to_string(),
                    component: (*component).to_string(),
                    dirent_type,
                });
            }
            current = file_id;
        }
        self.read_file(volume, current, path)
    }

    fn lookup(
        &mut self,
        volume: &Volume,
        parent: u64,
        name: &str,
        path: &str,
    ) -> Result<(u64, u16), ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: parent,
            kind: J_DIR_REC,
            reason,
        };
        for (key, value) in self.records(volume, parent, J_DIR_REC)? {
            let name_at = volume.layout.name_offset();
            let name_length = volume
                .layout
                .name_length(&key)
                .ok_or_else(|| malformed("the key is shorter than its name length field"))?;
            if name_length == 0 || name_at + name_length > key.len() {
                return Err(malformed("the name length leaves the key"));
            }
            if &key[name_at..name_at + name_length - 1] != name.as_bytes() {
                continue;
            }
            if value.len() < DREC_VALUE_BYTES {
                return Err(malformed("the value is shorter than a directory record"));
            }
            return Ok((
                u64_at(&value, DREC_FILE_ID_OFFSET),
                u16_at(&value, DREC_FLAGS_OFFSET) & DREC_TYPE_MASK,
            ));
        }
        Err(ApfsReadError::ComponentNotFound {
            path: path.to_string(),
            component: name.to_string(),
            parent_id: parent,
            volume: volume.name.clone(),
        })
    }

    fn read_file(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<Vec<u8>, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: file_id,
            kind: J_INODE,
            reason,
        };
        let (_, inode) = self
            .records(volume, file_id, J_INODE)?
            .into_iter()
            .next()
            .ok_or_else(|| ApfsReadError::NoInode {
                path: path.to_string(),
                file_id,
            })?;
        if inode.len() < INODE_XFIELDS_OFFSET {
            return Err(malformed(
                "the value is shorter than the fixed inode fields",
            ));
        }
        let mode = u16_at(&inode, INODE_MODE_OFFSET);
        if mode & S_IFMT != S_IFREG {
            return Err(ApfsReadError::NotARegularFile {
                path: path.to_string(),
                file_id,
                mode,
            });
        }
        let bsd_flags = u32_at(&inode, INODE_BSD_FLAGS_OFFSET);
        let stream_size = inode_data_stream(&inode)
            .map_err(malformed)?
            .map(|stream| stream.size);

        let header = match self.xattr(volume, file_id, DECMPFS_XATTR_NAME, path)? {
            Some(XattrData::Embedded(bytes)) => Some(bytes),
            Some(XattrData::Stream { object_id, size }) => {
                Some(self.read_data_stream(volume, object_id, size, path)?)
            }
            None => None,
        };
        if let Some(header) = header {
            return self.read_compressed(volume, file_id, path, &header);
        }
        if bsd_flags & UF_COMPRESSED != 0 {
            return Err(ApfsReadError::CompressionHeaderMissing {
                path: path.to_string(),
                file_id,
            });
        }

        let Some(size) = stream_size else {
            let extents = self.records(volume, file_id, J_FILE_EXTENT)?.len();
            if extents != 0 {
                return Err(ApfsReadError::NoDataStream {
                    path: path.to_string(),
                    file_id,
                    extents,
                });
            }
            return Ok(Vec::new());
        };
        self.read_data_stream(volume, file_id, size, path)
    }

    fn read_data_stream(
        &mut self,
        volume: &Volume,
        object_id: u64,
        size: u64,
        path: &str,
    ) -> Result<Vec<u8>, ApfsReadError> {
        if size > self.container_bytes {
            return Err(ApfsReadError::SizeOverflow {
                path: path.to_string(),
                object_id,
                size,
                limit: self.container_bytes,
            });
        }
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id,
            kind: J_FILE_EXTENT,
            reason,
        };
        let records = self.records(volume, object_id, J_FILE_EXTENT)?;
        if records.is_empty() && size != 0 {
            return Err(ApfsReadError::MissingExtents {
                path: path.to_string(),
                object_id,
                size,
            });
        }

        let mut spans = Vec::with_capacity(records.len());
        for (key, value) in &records {
            if key.len() < EXTENT_KEY_BYTES {
                return Err(malformed("the key is shorter than a file extent key"));
            }
            if value.len() < EXTENT_VALUE_BYTES {
                return Err(malformed("the value is shorter than a file extent value"));
            }
            spans.push((
                u64_at(key, EXTENT_LOGICAL_OFFSET),
                u64_at(value, EXTENT_LENGTH_OFFSET) & EXTENT_LENGTH_MASK,
                u64_at(value, EXTENT_PHYSICAL_OFFSET),
            ));
        }
        spans.sort_unstable();

        let block_size = self.verifier.block_size as u64;
        let mut out = vec![0u8; size as usize];
        for (logical, length, physical) in spans {
            if physical == 0 || logical >= size {
                continue;
            }
            let wanted = length.min(size - logical);
            for index in 0..wanted.div_ceil(block_size) {
                let block = self
                    .verifier
                    .read_raw(physical + index)
                    .map_err(faulted("a file extent's blocks"))?;
                let at = (logical + index * block_size) as usize;
                let take = (wanted - index * block_size).min(block_size) as usize;
                out[at..at + take].copy_from_slice(&block[..take]);
            }
        }
        Ok(out)
    }

    fn xattr(
        &mut self,
        volume: &Volume,
        file_id: u64,
        name: &'static str,
        path: &str,
    ) -> Result<Option<XattrData>, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: file_id,
            kind: J_XATTR,
            reason,
        };
        for (key, value) in self.records(volume, file_id, J_XATTR)? {
            if key.len() < XATTR_NAME_OFFSET {
                return Err(malformed("the key is shorter than its name length field"));
            }
            let name_length = u16_at(&key, XATTR_NAME_LENGTH_OFFSET) as usize;
            if name_length == 0 || XATTR_NAME_OFFSET + name_length > key.len() {
                return Err(malformed("the name length leaves the key"));
            }
            if &key[XATTR_NAME_OFFSET..XATTR_NAME_OFFSET + name_length - 1] != name.as_bytes() {
                continue;
            }
            if value.len() < XATTR_DATA_OFFSET {
                return Err(malformed("the value is shorter than an attribute header"));
            }
            let flags = u16_at(&value, XATTR_FLAGS_OFFSET);
            let data_length = u16_at(&value, XATTR_DATA_LENGTH_OFFSET) as usize;
            if XATTR_DATA_OFFSET + data_length > value.len() {
                return Err(malformed("the attribute data length leaves the value"));
            }
            let data = &value[XATTR_DATA_OFFSET..XATTR_DATA_OFFSET + data_length];
            if flags & XATTR_DATA_STREAM != 0 {
                if data.len() < XATTR_DSTREAM_BYTES {
                    return Err(malformed(
                        "the attribute names a stream but is too short to",
                    ));
                }
                return Ok(Some(XattrData::Stream {
                    object_id: u64_at(data, 0),
                    size: u64_at(data, 8 + DSTREAM_SIZE_OFFSET),
                }));
            }
            if flags & XATTR_DATA_EMBEDDED == 0 {
                return Err(ApfsReadError::UnsupportedXattrStorage {
                    path: path.to_string(),
                    file_id,
                    name,
                    flags,
                });
            }
            return Ok(Some(XattrData::Embedded(data.to_vec())));
        }
        Ok(None)
    }

    fn records(
        &mut self,
        volume: &Volume,
        object_id: u64,
        kind: u64,
    ) -> Result<Vec<Record>, ApfsReadError> {
        let target = (object_id, kind);
        let mut found = Vec::new();
        let mut pending = vec![(volume.fs_tree_paddr, None)];
        let mut visited = 0usize;

        while let Some((paddr, expected_level)) = pending.pop() {
            visited += 1;
            if visited > MAX_TREE_NODES {
                return Err(ApfsReadError::TreeWalkTooLong {
                    paddr,
                    limit: MAX_TREE_NODES,
                });
            }
            let (object_type, what) = match expected_level {
                None => (TYPE_BTREE, "filesystem tree root"),
                Some(_) => (TYPE_BTREE_NODE, "filesystem tree node"),
            };
            let object = if volume.headerless_catalog {
                self.verifier
                    .read_headerless_node(paddr)
                    .map_err(faulted("a sealed volume's filesystem tree node"))?
            } else {
                self.verifier
                    .read_expecting(paddr, None, object_type, what)
                    .map_err(faulted("a filesystem tree node"))?
            };
            let node = BTreeNode::decode_node(
                &object,
                self.verifier.block_size,
                volume.headerless_catalog,
            )
            .map_err(faulted("a filesystem tree node"))?;
            if let Some(level) = expected_level
                && node.level != level
            {
                return Err(ApfsReadError::TreeLevelMismatch {
                    paddr,
                    expected: level,
                    observed: node.level,
                });
            }

            let mut prefixes = Vec::with_capacity(node.nkeys);
            for index in 0..node.nkeys {
                let (key, _) = node
                    .entry(index)
                    .map_err(faulted("a filesystem tree record"))?;
                if key.len() < 8 {
                    return Err(ApfsReadError::RecordMalformed {
                        path: String::new(),
                        object_id,
                        kind,
                        reason: "a filesystem record key is shorter than its header",
                    });
                }
                let header = u64_at(key, 0);
                prefixes.push((header & J_OBJ_ID_MASK, header >> J_KIND_SHIFT));
            }

            for index in 0..node.nkeys {
                let (key, value) = node
                    .entry(index)
                    .map_err(faulted("a filesystem tree record"))?;
                if node.is_leaf() {
                    if prefixes[index] != target {
                        continue;
                    }
                    if found.len() >= MAX_RECORDS {
                        return Err(ApfsReadError::TooManyRecords {
                            object_id,
                            kind,
                            limit: MAX_RECORDS,
                        });
                    }
                    found.push((key.to_vec(), value.to_vec()));
                    continue;
                }
                let reaches_target = index == 0 || prefixes[index] <= target;
                let sibling_is_past = index + 1 == node.nkeys || prefixes[index + 1] >= target;
                if !reaches_target || !sibling_is_past {
                    continue;
                }
                if value.len() < 8 {
                    return Err(ApfsReadError::RecordMalformed {
                        path: String::new(),
                        object_id,
                        kind,
                        reason: "a filesystem tree index record has no child object id",
                    });
                }
                if node.level == 0 {
                    return Err(ApfsReadError::TreeLevelMismatch {
                        paddr,
                        expected: 1,
                        observed: 0,
                    });
                }
                let child_oid = self.child_object_id(volume, u64_at(value, 0), paddr)?;
                let child = resolve(&volume.omap, child_oid, volume.resolve_xid)
                    .map_err(faulted("a filesystem tree node's object map entry"))?;
                pending.push((child, Some(node.level - 1)));
            }
        }
        Ok(found)
    }
}

impl Reader<'_> {
    // A sealed tree's index value is relative to the tree root's own oid; read literally it still resolves to real nodes, just at the wrong level.
    fn child_object_id(
        &self,
        volume: &Volume,
        stored: u64,
        paddr: u64,
    ) -> Result<u64, ApfsReadError> {
        if !volume.headerless_catalog {
            return Ok(stored);
        }
        stored
            .checked_add(volume.fs_tree_oid)
            .ok_or(ApfsReadError::TreeWalkTooLong {
                paddr,
                limit: MAX_TREE_NODES,
            })
    }
}

type Record = (Vec<u8>, Vec<u8>);

enum XattrData {
    Embedded(Vec<u8>),
    Stream { object_id: u64, size: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataStreamFields {
    size: u64,
    default_crypto_id: u64,
}

fn inode_data_stream(inode: &[u8]) -> Result<Option<DataStreamFields>, &'static str> {
    if inode.len() < INODE_XFIELDS_OFFSET + XFIELD_BLOB_HEADER_BYTES {
        return Ok(None);
    }
    let count = u16_at(inode, INODE_XFIELDS_OFFSET) as usize;
    let entries_at = INODE_XFIELDS_OFFSET + XFIELD_BLOB_HEADER_BYTES;
    let mut data_at = entries_at + count * XFIELD_ENTRY_BYTES;
    if data_at > inode.len() {
        return Err("the extended field table leaves the inode record");
    }
    for index in 0..count {
        let entry = entries_at + index * XFIELD_ENTRY_BYTES;
        let field_type = inode[entry];
        let field_bytes = u16_at(inode, entry + 2) as usize;
        if data_at + field_bytes > inode.len() {
            return Err("an extended field's data leaves the inode record");
        }
        if field_type == INO_EXT_TYPE_DSTREAM {
            if field_bytes < DSTREAM_BYTES {
                return Err("the data stream extended field is shorter than a data stream");
            }
            return Ok(Some(DataStreamFields {
                size: u64_at(inode, data_at + DSTREAM_SIZE_OFFSET),
                default_crypto_id: u64_at(inode, data_at + DSTREAM_DEFAULT_CRYPTO_ID_OFFSET),
            }));
        }
        data_at += field_bytes.next_multiple_of(XFIELD_DATA_ALIGNMENT);
    }
    Ok(None)
}

fn describe_list(names: &[String]) -> String {
    if names.is_empty() {
        return "none".to_string();
    }
    names
        .iter()
        .map(|name| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(", ")
}

const STREAM_RUN_BLOCKS: usize = 1024;

pub const MAX_COMPRESSED_FILE_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VolumeChoice {
    Named(String),
    Role(u16),
    Index(usize),
}

impl fmt::Display for VolumeChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named(name) => write!(f, "the volume named {name:?}"),
            Self::Role(role) => write!(f, "the volume with role {role:#x}"),
            Self::Index(index) => write!(f, "the volume at index {index}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeSummary {
    pub index: usize,
    pub oid: u64,
    pub name: String,
    pub role: u16,
    pub sealed: bool,
    pub encrypted: bool,
    pub fs_flags: u64,
    pub uuid: [u8; 16],
    pub incompatible_features: u64,
    pub has_extent_tree: bool,
    pub declared_snapshots: u64,
    pub volume_group_id: [u8; 16],
}

pub struct MountedVolume {
    volume: Volume,
    snapshot: Option<SnapshotMount>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotMount {
    pub name: String,
    pub xid: u64,
    pub sblock_paddr: u64,
}

impl MountedVolume {
    pub fn oid(&self) -> u64 {
        self.volume.oid
    }

    pub fn name(&self) -> &str {
        &self.volume.name
    }

    pub fn role(&self) -> u16 {
        self.volume.role
    }

    pub fn sealed(&self) -> bool {
        self.volume.sealed
    }

    pub fn encrypted(&self) -> bool {
        self.volume.encrypted
    }

    pub fn fs_flags(&self) -> u64 {
        self.volume.fs_flags
    }

    pub fn uuid(&self) -> [u8; 16] {
        self.volume.uuid
    }

    pub fn volume_group_id(&self) -> [u8; 16] {
        self.volume.volume_group_id
    }

    pub fn snapshot(&self) -> Option<&SnapshotMount> {
        self.snapshot.as_ref()
    }

    pub fn fs_tree_paddr(&self) -> u64 {
        self.volume.fs_tree_paddr
    }

    pub fn apsb_paddr(&self) -> u64 {
        self.volume.apsb_paddr
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub file_id: u64,
    pub entry_type: u16,
    pub size: Option<u64>,
    pub compressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFacts {
    pub file_id: u64,
    pub private_id: u64,
    pub mode: u16,
    pub bsd_flags: u32,
    pub stream_size: Option<u64>,
    pub default_crypto_id: Option<u64>,
    pub compression_type: Option<u32>,
    pub uncompressed_size: Option<u64>,
}

impl FileFacts {
    pub fn readable_size(&self) -> u64 {
        self.uncompressed_size
            .unwrap_or_else(|| self.stream_size.unwrap_or(0))
    }

    pub fn is_directory(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    pub fn is_regular_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptedExtentPolicy {
    #[default]
    Refuse,
    // A volume written by real Apple silicon returns ciphertext here and no error.
    Verbatim,
    Unwrap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoFacts {
    pub file_id: u64,
    pub default_crypto_id: Option<u64>,
    pub extent_crypto_ids: Vec<(u64, usize)>,
    pub extents_keyed_by_block: usize,
    pub extents_without_crypto_id: usize,
    pub crypto_states: Vec<CryptoStateFacts>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoStateFacts {
    pub object_id: u64,
    pub refcount: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub crypto_flags: u32,
    pub persistent_class: u32,
    pub key_os_version: u32,
    pub key_revision: u16,
    pub key_len: u16,
    pub persistent_key_version: Option<u8>,
    pub persistent_key_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractReport {
    pub file_id: u64,
    pub logical_size: u64,
    pub start: u64,
    pub bytes_written: u64,
    pub compression_type: Option<u32>,
    pub extents: usize,
    pub sparse_bytes: u64,
}

pub struct ApfsContainer<'a> {
    reader: Reader<'a>,
}

impl<'a> ApfsContainer<'a> {
    pub fn mount(
        source: &'a mut dyn BlockSource,
        block_size: u32,
        block_count: u64,
    ) -> Result<Self, ApfsReadError> {
        Ok(Self {
            reader: Reader::mount(source, block_size, block_count)?,
        })
    }

    pub fn xid(&self) -> u64 {
        self.reader.xid
    }

    pub fn superblock_paddr(&self) -> u64 {
        self.reader.superblock_paddr
    }

    pub fn block_size(&self) -> u32 {
        self.reader.verifier.block_size as u32
    }

    pub fn volumes(&mut self) -> Result<Vec<VolumeSummary>, ApfsReadError> {
        let mut summaries = Vec::new();
        for (index, oid) in self.reader.volume_oids.clone().into_iter().enumerate() {
            let volume = self.reader.open_volume(oid)?;
            summaries.push(VolumeSummary {
                index,
                oid,
                name: volume.name.clone(),
                role: volume.role,
                sealed: volume.sealed,
                encrypted: volume.encrypted,
                fs_flags: volume.fs_flags,
                uuid: volume.uuid,
                incompatible_features: volume.incompatible_features,
                has_extent_tree: matches!(volume.extents, ExtentSource::FextTree { .. }),
                declared_snapshots: volume.declared_snapshots,
                volume_group_id: volume.volume_group_id,
            });
        }
        Ok(summaries)
    }

    pub fn open_volume_chosen(
        &mut self,
        choice: &VolumeChoice,
    ) -> Result<MountedVolume, ApfsReadError> {
        let summaries = self.volumes()?;
        let matched: Vec<&VolumeSummary> = summaries
            .iter()
            .filter(|summary| match choice {
                VolumeChoice::Named(name) => summary.name == *name,
                VolumeChoice::Role(role) => summary.role == *role,
                VolumeChoice::Index(index) => summary.index == *index,
            })
            .collect();
        let describe = |summary: &VolumeSummary| {
            format!(
                "{} (role {:#x}, index {})",
                summary.name, summary.role, summary.index
            )
        };
        match matched.as_slice() {
            [] => Err(ApfsReadError::VolumeNotSelected {
                wanted: choice.to_string(),
                available: summaries.iter().map(describe).collect(),
            }),
            [only] => {
                let volume = self.reader.open_volume(only.oid)?;
                Ok(MountedVolume {
                    volume,
                    snapshot: None,
                })
            }
            several => Err(ApfsReadError::VolumeAmbiguous {
                wanted: choice.to_string(),
                matched: several.iter().map(|summary| describe(summary)).collect(),
            }),
        }
    }

    pub fn snapshots(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<Vec<SnapshotRecord>, ApfsReadError> {
        let found = self
            .reader
            .verifier
            .read_volume_snapshots(
                volume.volume.snap_meta_tree_paddr,
                volume.volume.declared_snapshots,
            )
            .map_err(faulted("a volume's snapshot metadata tree"))?;
        Ok(found.snapshots)
    }

    pub fn open_snapshot(
        &mut self,
        volume: &MountedVolume,
        name: &str,
    ) -> Result<MountedVolume, ApfsReadError> {
        let snapshots = self.snapshots(volume)?;
        let Some(record) = snapshots.iter().find(|record| record.name == name) else {
            return Err(ApfsReadError::SnapshotNotFound {
                volume: volume.volume.name.clone(),
                wanted: name.to_string(),
                available: snapshots.iter().map(|record| record.name.clone()).collect(),
            });
        };
        if record.sblock_oid == 0 {
            return Err(ApfsReadError::SnapshotWithoutSuperblock {
                volume: volume.volume.name.clone(),
                snapshot: name.to_string(),
            });
        }
        let object = self
            .reader
            .verifier
            .read_expecting(
                record.sblock_oid,
                None,
                TYPE_FS,
                "a snapshot's volume superblock",
            )
            .map_err(faulted("a snapshot's volume superblock"))?;
        let mounted = self.reader.decode_volume(
            object.bytes,
            record.sblock_oid,
            record.sblock_oid,
            record.xid,
        )?;
        Ok(MountedVolume {
            volume: mounted,
            snapshot: Some(SnapshotMount {
                name: record.name.clone(),
                xid: record.xid,
                sblock_paddr: record.sblock_oid,
            }),
        })
    }

    pub fn open_root_snapshot(
        &mut self,
        volume: &MountedVolume,
    ) -> Result<MountedVolume, ApfsReadError> {
        let snapshots = self.snapshots(volume)?;
        let newest = snapshots
            .iter()
            .filter(|record| record.name.starts_with(ROOT_SNAPSHOT_PREFIX))
            .fold(None::<&SnapshotRecord>, |best, record| match best {
                Some(best) if best.xid >= record.xid => Some(best),
                _ => Some(record),
            });
        let Some(newest) = newest else {
            return Err(ApfsReadError::NoRootSnapshot {
                volume: volume.volume.name.clone(),
            });
        };
        let name = newest.name.clone();
        self.open_snapshot(volume, &name)
    }

    pub fn resolve(
        &mut self,
        volume: &MountedVolume,
        path: &str,
    ) -> Result<(u64, u16), ApfsReadError> {
        self.reader.walk(&volume.volume, path)
    }

    pub fn stat(&mut self, volume: &MountedVolume, path: &str) -> Result<FileFacts, ApfsReadError> {
        let (file_id, _) = self.reader.walk(&volume.volume, path)?;
        self.reader.inode_facts(&volume.volume, file_id, path)
    }

    pub fn list_directory(
        &mut self,
        volume: &MountedVolume,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>, ApfsReadError> {
        let directory_id = if path == "/" {
            ROOT_DIR_INO_NUM
        } else {
            let (file_id, _) = self.reader.walk(&volume.volume, path)?;
            let facts = self.reader.inode_facts(&volume.volume, file_id, path)?;
            if facts.mode & S_IFMT != S_IFDIR {
                return Err(ApfsReadError::NotADirectoryToList {
                    path: path.to_string(),
                    file_id,
                    mode: facts.mode,
                });
            }
            file_id
        };
        self.reader.entries_of(&volume.volume, directory_id, path)
    }

    pub fn read_symlink(
        &mut self,
        volume: &MountedVolume,
        path: &str,
    ) -> Result<String, ApfsReadError> {
        let (file_id, entry_type) = self.reader.walk(&volume.volume, path)?;
        let facts = self.reader.inode_facts(&volume.volume, file_id, path)?;
        if facts.mode & S_IFMT != S_IFLNK && entry_type != DT_LNK {
            return Err(ApfsReadError::NotASymlink {
                path: path.to_string(),
                file_id,
                mode: facts.mode,
            });
        }
        let bytes = match self.reader.xattr(&volume.volume, file_id, "com.apple.fs.symlink", path)? {
            Some(XattrData::Embedded(bytes)) => bytes,
            Some(XattrData::Stream { object_id, size }) => {
                self.reader.read_data_stream(&volume.volume, object_id, size, path)?
            }
            None => {
                let size = facts.stream_size.unwrap_or(0);
                self.reader.read_data_stream(&volume.volume, file_id, size, path)?
            }
        };
        let bytes = bytes.strip_suffix(&[0]).unwrap_or(&bytes);
        let malformed = |reason| ApfsReadError::RecordMalformed {
            path: path.to_string(), object_id: file_id, kind: J_XATTR, reason,
        };
        if bytes.is_empty() || bytes.contains(&0) {
            return Err(malformed("symlink target is empty or contains an embedded NUL"));
        }
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| malformed("symlink target is not UTF-8"))
    }

    pub fn extract(
        &mut self,
        volume: &MountedVolume,
        path: &str,
        start: u64,
        length: Option<u64>,
        out: &mut dyn Write,
    ) -> Result<ExtractReport, ApfsReadError> {
        self.extract_with_policy(
            volume,
            path,
            start,
            length,
            out,
            EncryptedExtentPolicy::Refuse,
        )
    }

    pub fn extract_with_policy(
        &mut self,
        volume: &MountedVolume,
        path: &str,
        start: u64,
        length: Option<u64>,
        out: &mut dyn Write,
        encrypted: EncryptedExtentPolicy,
    ) -> Result<ExtractReport, ApfsReadError> {
        if volume.volume.encrypted && encrypted == EncryptedExtentPolicy::Refuse {
            return Err(ApfsReadError::VolumeEncrypted {
                volume: volume.volume.name.clone(),
                fs_flags: volume.volume.fs_flags,
            });
        }
        let (file_id, _) = self.reader.walk(&volume.volume, path)?;
        self.reader
            .extract_range(&volume.volume, file_id, path, start, length, out)
    }

    pub fn crypto_facts(
        &mut self,
        volume: &MountedVolume,
        path: &str,
    ) -> Result<CryptoFacts, ApfsReadError> {
        let (file_id, _) = self.reader.walk(&volume.volume, path)?;
        self.reader.crypto_facts(&volume.volume, file_id, path)
    }
}

impl Reader<'_> {
    fn walk(&mut self, volume: &Volume, path: &str) -> Result<(u64, u16), ApfsReadError> {
        let components = path_components(path)?;
        let mut current = ROOT_DIR_INO_NUM;
        let mut kind = DT_DIR;
        for (index, component) in components.iter().enumerate() {
            let (file_id, dirent_type) = self.lookup(volume, current, component, path)?;
            if index + 1 < components.len() && dirent_type != DT_DIR {
                return Err(ApfsReadError::NotADirectory {
                    path: path.to_string(),
                    component: (*component).to_string(),
                    dirent_type,
                });
            }
            current = file_id;
            kind = dirent_type;
        }
        Ok((current, kind))
    }

    fn inode_facts(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<FileFacts, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: file_id,
            kind: J_INODE,
            reason,
        };
        let (_, inode) = self
            .records(volume, file_id, J_INODE)?
            .into_iter()
            .next()
            .ok_or_else(|| ApfsReadError::NoInode {
                path: path.to_string(),
                file_id,
            })?;
        if inode.len() < INODE_XFIELDS_OFFSET {
            return Err(malformed(
                "the value is shorter than the fixed inode fields",
            ));
        }
        let bsd_flags = u32_at(&inode, INODE_BSD_FLAGS_OFFSET);
        let data_stream = inode_data_stream(&inode).map_err(malformed)?;

        let (compression_type, uncompressed_size) = if bsd_flags & UF_COMPRESSED == 0 {
            (None, None)
        } else {
            let header = self.decmpfs_header(volume, file_id, path)?;
            match header {
                Some(header) => {
                    let (kind, size) = decmpfs_header_fields(&header, file_id, path)?;
                    (Some(kind), Some(size))
                }
                None => {
                    return Err(ApfsReadError::CompressionHeaderMissing {
                        path: path.to_string(),
                        file_id,
                    });
                }
            }
        };

        Ok(FileFacts {
            file_id,
            private_id: u64_at(&inode, INODE_PRIVATE_ID_OFFSET),
            mode: u16_at(&inode, INODE_MODE_OFFSET),
            bsd_flags,
            stream_size: data_stream.map(|stream| stream.size),
            default_crypto_id: data_stream.map(|stream| stream.default_crypto_id),
            compression_type,
            uncompressed_size,
        })
    }

    fn decmpfs_header(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<Option<Vec<u8>>, ApfsReadError> {
        match self.xattr(volume, file_id, DECMPFS_XATTR_NAME, path)? {
            Some(XattrData::Embedded(bytes)) => Ok(Some(bytes)),
            Some(XattrData::Stream { object_id, size }) => {
                Ok(Some(self.read_data_stream(volume, object_id, size, path)?))
            }
            None => Ok(None),
        }
    }

    fn entries_of(
        &mut self,
        volume: &Volume,
        directory_id: u64,
        path: &str,
    ) -> Result<Vec<DirectoryEntry>, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: directory_id,
            kind: J_DIR_REC,
            reason,
        };
        let mut named = Vec::new();
        for (key, value) in self.records(volume, directory_id, J_DIR_REC)? {
            let name_at = volume.layout.name_offset();
            let name_length = volume
                .layout
                .name_length(&key)
                .ok_or_else(|| malformed("the key is shorter than its name length field"))?;
            if name_length == 0 || name_at + name_length > key.len() {
                return Err(malformed("the name length leaves the key"));
            }
            if value.len() < DREC_VALUE_BYTES {
                return Err(malformed("the value is shorter than a directory record"));
            }
            named.push((
                String::from_utf8_lossy(&key[name_at..name_at + name_length - 1]).into_owned(),
                u64_at(&value, DREC_FILE_ID_OFFSET),
                u16_at(&value, DREC_FLAGS_OFFSET) & DREC_TYPE_MASK,
            ));
        }

        let mut entries = Vec::with_capacity(named.len());
        for (name, file_id, entry_type) in named {
            let child_path = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            let facts = self.inode_facts(volume, file_id, &child_path)?;
            entries.push(DirectoryEntry {
                name,
                file_id,
                entry_type,
                size: facts.uncompressed_size.or(facts.stream_size),
                compressed: facts.compression_type.is_some(),
            });
        }
        Ok(entries)
    }

    fn extract_range(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
        start: u64,
        length: Option<u64>,
        out: &mut dyn Write,
    ) -> Result<ExtractReport, ApfsReadError> {
        let facts = self.inode_facts(volume, file_id, path)?;
        if facts.mode & S_IFMT != S_IFREG {
            return Err(ApfsReadError::NotARegularFile {
                path: path.to_string(),
                file_id,
                mode: facts.mode,
            });
        }

        if facts.compression_type.is_some() {
            return self.extract_compressed(volume, &facts, path, start, length, out);
        }

        let Some(size) = facts.stream_size else {
            let extents = self.extent_spans(volume, &facts, path)?.len();
            if extents != 0 {
                return Err(ApfsReadError::NoDataStream {
                    path: path.to_string(),
                    file_id,
                    extents,
                });
            }
            if start > 0 {
                return Err(ApfsReadError::RangeStartsPastEnd {
                    path: path.to_string(),
                    start,
                    size: 0,
                });
            }
            return Ok(ExtractReport {
                file_id,
                logical_size: 0,
                start,
                bytes_written: 0,
                compression_type: None,
                extents: 0,
                sparse_bytes: 0,
            });
        };

        if size > self.container_bytes {
            return Err(ApfsReadError::SizeOverflow {
                path: path.to_string(),
                object_id: file_id,
                size,
                limit: self.container_bytes,
            });
        }
        if start > size {
            return Err(ApfsReadError::RangeStartsPastEnd {
                path: path.to_string(),
                start,
                size,
            });
        }
        let end = match length {
            Some(length) => start.saturating_add(length).min(size),
            None => size,
        };

        let spans = self.extent_spans(volume, &facts, path)?;
        if spans.is_empty() && size != 0 {
            return Err(ApfsReadError::MissingExtents {
                path: path.to_string(),
                object_id: file_id,
                size,
            });
        }
        let extents = spans.len();
        let (bytes_written, sparse_bytes) =
            self.stream_spans(&spans, size, start, end, path, out)?;
        Ok(ExtractReport {
            file_id,
            logical_size: size,
            start,
            bytes_written,
            compression_type: None,
            extents,
            sparse_bytes,
        })
    }

    fn extract_compressed(
        &mut self,
        volume: &Volume,
        facts: &FileFacts,
        path: &str,
        start: u64,
        length: Option<u64>,
        out: &mut dyn Write,
    ) -> Result<ExtractReport, ApfsReadError> {
        let declared = facts.uncompressed_size.unwrap_or(0);
        if declared > MAX_COMPRESSED_FILE_BYTES {
            return Err(ApfsReadError::CompressedTooLargeToBuffer {
                path: path.to_string(),
                file_id: facts.file_id,
                size: declared,
                limit: MAX_COMPRESSED_FILE_BYTES,
            });
        }
        let header = self
            .decmpfs_header(volume, facts.file_id, path)?
            .ok_or_else(|| ApfsReadError::CompressionHeaderMissing {
                path: path.to_string(),
                file_id: facts.file_id,
            })?;
        let bytes = self.read_compressed(volume, facts.file_id, path, &header)?;
        let size = bytes.len() as u64;
        if start > size {
            return Err(ApfsReadError::RangeStartsPastEnd {
                path: path.to_string(),
                start,
                size,
            });
        }
        let end = match length {
            Some(length) => start.saturating_add(length).min(size),
            None => size,
        };
        let slice = &bytes[start as usize..end as usize];
        out.write_all(slice)
            .map_err(|error| ApfsReadError::Output {
                what: "the decompressed file",
                reason: error.to_string(),
            })?;
        Ok(ExtractReport {
            file_id: facts.file_id,
            logical_size: size,
            start,
            bytes_written: slice.len() as u64,
            compression_type: facts.compression_type,
            extents: 0,
            sparse_bytes: 0,
        })
    }

    fn crypto_facts(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<CryptoFacts, ApfsReadError> {
        let facts = self.inode_facts(volume, file_id, path)?;
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: file_id,
            kind: J_FILE_EXTENT,
            reason,
        };

        let mut named: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
        let mut keyed_by_block = 0usize;
        let mut without = 0usize;
        match volume.extents {
            ExtentSource::Catalog => {
                for (key, value) in self.records(volume, file_id, J_FILE_EXTENT)? {
                    if key.len() < EXTENT_KEY_BYTES {
                        return Err(malformed("the key is shorter than a file extent key"));
                    }
                    if value.len() < EXTENT_VALUE_BYTES {
                        return Err(malformed("the value is shorter than a file extent value"));
                    }
                    if value.len() < EXTENT_VALUE_WITH_CRYPTO_BYTES {
                        without += 1;
                        continue;
                    }
                    let crypto_id = u64_at(&value, EXTENT_CRYPTO_ID_OFFSET);
                    if crypto_id == u64_at(&value, EXTENT_PHYSICAL_OFFSET) {
                        keyed_by_block += 1;
                    } else {
                        *named.entry(crypto_id).or_default() += 1;
                    }
                }
            }
            ExtentSource::FextTree { paddr } => {
                without = self
                    .fext_spans(volume, paddr, facts.private_id, path)?
                    .len();
            }
        }

        let mut wanted: std::collections::BTreeSet<u64> = named.keys().copied().collect();
        if let Some(default_id) = facts.default_crypto_id {
            wanted.insert(default_id);
        }
        let mut crypto_states = Vec::new();
        for object_id in wanted {
            if let Some(state) = self.crypto_state(volume, object_id, path)? {
                crypto_states.push(state);
            }
        }

        Ok(CryptoFacts {
            file_id,
            default_crypto_id: facts.default_crypto_id,
            extent_crypto_ids: named.into_iter().collect(),
            extents_keyed_by_block: keyed_by_block,
            extents_without_crypto_id: without,
            crypto_states,
        })
    }

    fn crypto_state(
        &mut self,
        volume: &Volume,
        object_id: u64,
        path: &str,
    ) -> Result<Option<CryptoStateFacts>, ApfsReadError> {
        let Some((_, value)) = self
            .records(volume, object_id, J_CRYPTO_STATE)?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        if value.len() < CRYPTO_PERSISTENT_KEY_OFFSET {
            return Err(ApfsReadError::RecordMalformed {
                path: path.to_string(),
                object_id,
                kind: J_CRYPTO_STATE,
                reason: "the value is shorter than the fixed crypto state fields",
            });
        }
        let carried = value.len() - CRYPTO_PERSISTENT_KEY_OFFSET;
        Ok(Some(CryptoStateFacts {
            object_id,
            refcount: u32_at(&value, CRYPTO_REFCNT_OFFSET),
            major_version: u16_at(&value, CRYPTO_MAJOR_VERSION_OFFSET),
            minor_version: u16_at(&value, CRYPTO_MINOR_VERSION_OFFSET),
            crypto_flags: u32_at(&value, CRYPTO_FLAGS_OFFSET),
            persistent_class: u32_at(&value, CRYPTO_PERSISTENT_CLASS_OFFSET),
            key_os_version: u32_at(&value, CRYPTO_KEY_OS_VERSION_OFFSET),
            key_revision: u16_at(&value, CRYPTO_KEY_REVISION_OFFSET),
            key_len: u16_at(&value, CRYPTO_KEY_LEN_OFFSET),
            persistent_key_version: value.get(CRYPTO_PERSISTENT_KEY_OFFSET).copied(),
            persistent_key_bytes: carried,
        }))
    }

    fn extent_spans(
        &mut self,
        volume: &Volume,
        facts: &FileFacts,
        path: &str,
    ) -> Result<Vec<(u64, u64, u64)>, ApfsReadError> {
        let mut spans = match volume.extents {
            ExtentSource::Catalog => self.catalog_spans(volume, facts.file_id, path)?,
            ExtentSource::FextTree { paddr } => {
                self.fext_spans(volume, paddr, facts.private_id, path)?
            }
        };
        spans.sort_unstable();
        Ok(spans)
    }

    fn catalog_spans(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<Vec<(u64, u64, u64)>, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: file_id,
            kind: J_FILE_EXTENT,
            reason,
        };
        let records = self.records(volume, file_id, J_FILE_EXTENT)?;
        let mut spans = Vec::with_capacity(records.len());
        for (key, value) in &records {
            if key.len() < EXTENT_KEY_BYTES {
                return Err(malformed("the key is shorter than a file extent key"));
            }
            if value.len() < EXTENT_VALUE_BYTES {
                return Err(malformed("the value is shorter than a file extent value"));
            }
            spans.push((
                u64_at(key, EXTENT_LOGICAL_OFFSET),
                u64_at(value, EXTENT_LENGTH_OFFSET) & EXTENT_LENGTH_MASK,
                u64_at(value, EXTENT_PHYSICAL_OFFSET),
            ));
        }
        Ok(spans)
    }

    fn fext_spans(
        &mut self,
        volume: &Volume,
        root_paddr: u64,
        private_id: u64,
        path: &str,
    ) -> Result<Vec<(u64, u64, u64)>, ApfsReadError> {
        let malformed = |reason: &'static str| ApfsReadError::RecordMalformed {
            path: path.to_string(),
            object_id: private_id,
            kind: J_FILE_EXTENT,
            reason,
        };
        let _ = volume;
        let mut spans = Vec::new();
        let mut pending = vec![(root_paddr, None)];
        let mut visited = 0usize;

        while let Some((paddr, expected_level)) = pending.pop() {
            visited += 1;
            if visited > MAX_TREE_NODES {
                return Err(ApfsReadError::TreeWalkTooLong {
                    paddr,
                    limit: MAX_TREE_NODES,
                });
            }
            let (object_type, what) = match expected_level {
                None => (TYPE_BTREE, "file extent tree root"),
                Some(_) => (TYPE_BTREE_NODE, "file extent tree node"),
            };
            let object = self
                .verifier
                .read_expecting(paddr, Some(paddr), object_type, what)
                .map_err(faulted("a sealed volume's file extent tree node"))?;
            if object.storage() != OBJ_PHYSICAL {
                return Err(ApfsReadError::VolumeNotVirtual {
                    paddr,
                    storage: object.storage(),
                });
            }
            if object.subtype() & OBJ_TYPE_MASK != TYPE_FEXT_TREE {
                return Err(ApfsReadError::Container {
                    what: "a sealed volume's file extent tree subtype",
                    source: VerifyError::ObjectMismatch {
                        paddr,
                        field: "file extent tree subtype",
                        expected: u64::from(TYPE_FEXT_TREE),
                        observed: u64::from(object.subtype() & OBJ_TYPE_MASK),
                    },
                });
            }
            let node = BTreeNode::decode(&object, self.verifier.block_size)
                .map_err(faulted("a sealed volume's file extent tree node"))?;
            if let Some(level) = expected_level
                && node.level != level
            {
                return Err(ApfsReadError::TreeLevelMismatch {
                    paddr,
                    expected: level,
                    observed: node.level,
                });
            }

            let mut owners = Vec::with_capacity(node.nkeys);
            for index in 0..node.nkeys {
                let (key, _) = node
                    .entry(index)
                    .map_err(faulted("a file extent tree record"))?;
                if key.len() < FEXT_KEY_BYTES {
                    return Err(malformed("a file extent tree key is shorter than one"));
                }
                owners.push(u64_at(key, FEXT_PRIVATE_ID_OFFSET));
            }

            for index in 0..node.nkeys {
                let (key, value) = node
                    .entry(index)
                    .map_err(faulted("a file extent tree record"))?;
                if node.is_leaf() {
                    if owners[index] != private_id {
                        continue;
                    }
                    if value.len() < FEXT_VALUE_BYTES {
                        return Err(malformed("a file extent tree value is shorter than one"));
                    }
                    if spans.len() >= MAX_RECORDS {
                        return Err(ApfsReadError::TooManyRecords {
                            object_id: private_id,
                            kind: J_FILE_EXTENT,
                            limit: MAX_RECORDS,
                        });
                    }
                    spans.push((
                        u64_at(key, FEXT_LOGICAL_OFFSET),
                        u64_at(value, FEXT_LENGTH_OFFSET) & EXTENT_LENGTH_MASK,
                        u64_at(value, FEXT_PHYSICAL_OFFSET),
                    ));
                    continue;
                }
                let reaches_target = index == 0 || owners[index] <= private_id;
                let sibling_is_past = index + 1 == node.nkeys || owners[index + 1] >= private_id;
                if !reaches_target || !sibling_is_past {
                    continue;
                }
                if value.len() < 8 {
                    return Err(malformed("a file extent tree index record has no child"));
                }
                if node.level == 0 {
                    return Err(ApfsReadError::TreeLevelMismatch {
                        paddr,
                        expected: 1,
                        observed: 0,
                    });
                }
                pending.push((u64_at(value, 0), Some(node.level - 1)));
            }
        }
        Ok(spans)
    }

    fn stream_spans(
        &mut self,
        spans: &[(u64, u64, u64)],
        size: u64,
        start: u64,
        end: u64,
        path: &str,
        out: &mut dyn Write,
    ) -> Result<(u64, u64), ApfsReadError> {
        let block_size = self.verifier.block_size;
        let mut buffer = vec![0u8; STREAM_RUN_BLOCKS * block_size];
        let mut cursor = start;
        let mut sparse = 0u64;

        for (logical, length, physical) in spans {
            if cursor >= end {
                break;
            }
            if *physical == 0 || *logical >= size {
                continue;
            }
            let covered = (*length).min(size - logical);
            let span_end = logical + covered;
            let from = cursor.max(*logical);
            let to = end.min(span_end);
            if from >= to {
                continue;
            }
            if from > cursor {
                write_zeroes(out, from - cursor, &mut buffer)?;
                sparse += from - cursor;
            }
            let mut at = from;
            while at < to {
                let within = at - logical;
                let block = physical + within / block_size as u64;
                let skip = (within % block_size as u64) as usize;
                let wanted = (to - at) as usize;
                let blocks = (skip + wanted).div_ceil(block_size).min(STREAM_RUN_BLOCKS);
                let bytes = blocks * block_size;
                self.read_extent_run(block, blocks, &mut buffer[..bytes], path)?;
                let take = wanted.min(bytes - skip);
                out.write_all(&buffer[skip..skip + take]).map_err(|error| {
                    ApfsReadError::Output {
                        what: "a file extent",
                        reason: error.to_string(),
                    }
                })?;
                at += take as u64;
            }
            cursor = to;
        }

        if cursor < end {
            write_zeroes(out, end - cursor, &mut buffer)?;
            sparse += end - cursor;
            cursor = end;
        }
        Ok((cursor - start, sparse))
    }

    fn read_extent_run(
        &mut self,
        block: u64,
        blocks: usize,
        into: &mut [u8],
        path: &str,
    ) -> Result<(), ApfsReadError> {
        let last = block
            .checked_add(blocks as u64)
            .ok_or(ApfsReadError::SizeOverflow {
                path: path.to_string(),
                object_id: 0,
                size: blocks as u64,
                limit: self.verifier.block_count,
            })?;
        if last > self.verifier.block_count {
            return Err(ApfsReadError::Container {
                what: "a file extent's blocks",
                source: VerifyError::BlockOutOfRange { index: block },
            });
        }
        self.verifier
            .source
            .read_run(block, blocks, into)
            .map_err(faulted("a file extent's blocks"))
    }
}

fn write_zeroes(out: &mut dyn Write, count: u64, buffer: &mut [u8]) -> Result<(), ApfsReadError> {
    let mut left = count;
    while left > 0 {
        let take = left.min(buffer.len() as u64) as usize;
        buffer[..take].fill(0);
        out.write_all(&buffer[..take])
            .map_err(|error| ApfsReadError::Output {
                what: "a sparse region",
                reason: error.to_string(),
            })?;
        left -= take as u64;
    }
    Ok(())
}

fn decmpfs_header_fields(
    header: &[u8],
    file_id: u64,
    path: &str,
) -> Result<(u32, u64), ApfsReadError> {
    if header.len() < DECMPFS_HEADER_BYTES {
        return Err(ApfsReadError::CompressionHeaderTruncated {
            path: path.to_string(),
            file_id,
            length: header.len(),
        });
    }
    let magic = u32_at(header, 0);
    if magic != DECMPFS_MAGIC {
        return Err(ApfsReadError::CompressionHeaderBadMagic {
            path: path.to_string(),
            file_id,
            observed: magic,
        });
    }
    Ok((
        u32_at(header, DECMPFS_TYPE_OFFSET),
        u64_at(header, DECMPFS_SIZE_OFFSET),
    ))
}

impl Reader<'_> {
    fn read_compressed(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
        header: &[u8],
    ) -> Result<Vec<u8>, ApfsReadError> {
        if header.len() < DECMPFS_HEADER_BYTES {
            return Err(ApfsReadError::CompressionHeaderTruncated {
                path: path.to_string(),
                file_id,
                length: header.len(),
            });
        }
        let magic = u32_at(header, 0);
        if magic != DECMPFS_MAGIC {
            return Err(ApfsReadError::CompressionHeaderBadMagic {
                path: path.to_string(),
                file_id,
                observed: magic,
            });
        }
        let compression_type = u32_at(header, DECMPFS_TYPE_OFFSET);
        let size = u64_at(header, DECMPFS_SIZE_OFFSET);
        if size > self.container_bytes {
            return Err(ApfsReadError::SizeOverflow {
                path: path.to_string(),
                object_id: file_id,
                size,
                limit: self.container_bytes,
            });
        }
        let inline = &header[DECMPFS_HEADER_BYTES..];

        let bytes = match compression_type {
            DECMPFS_TYPE_INLINE_RAW => inline.to_vec(),
            DECMPFS_TYPE_INLINE_ZLIB => {
                let mut out = Vec::with_capacity(size as usize);
                expand_block(inline, size as usize, &mut out).map_err(|source| {
                    ApfsReadError::CompressedStreamBroken {
                        path: path.to_string(),
                        file_id,
                        block: 0,
                        source,
                    }
                })?;
                out
            }
            DECMPFS_TYPE_RESOURCE_ZLIB => {
                let fork = self.read_resource_fork(volume, file_id, path)?;
                expand_resource_fork(&fork, size as usize, file_id, path)?
            }
            DECMPFS_TYPE_INLINE_LZVN => {
                let mut out = Vec::with_capacity(size as usize);
                expand_lzvn_block(inline, size as usize, &mut out).map_err(|source| {
                    ApfsReadError::LzvnStreamBroken {
                        path: path.to_string(),
                        file_id,
                        block: 0,
                        source,
                    }
                })?;
                out
            }
            DECMPFS_TYPE_RESOURCE_LZVN => {
                let fork = self.read_resource_fork(volume, file_id, path)?;
                expand_lzvn_fork(&fork, size as usize, file_id, path)?
            }
            other => {
                return Err(ApfsReadError::UnsupportedCompression {
                    path: path.to_string(),
                    file_id,
                    compression_type: other,
                });
            }
        };

        if bytes.len() as u64 != size {
            return Err(ApfsReadError::CompressedSizeMismatch {
                path: path.to_string(),
                file_id,
                declared: size,
                produced: bytes.len(),
            });
        }
        Ok(bytes)
    }

    fn read_resource_fork(
        &mut self,
        volume: &Volume,
        file_id: u64,
        path: &str,
    ) -> Result<Vec<u8>, ApfsReadError> {
        match self.xattr(volume, file_id, RESOURCE_FORK_XATTR_NAME, path)? {
            Some(XattrData::Embedded(bytes)) => Ok(bytes),
            Some(XattrData::Stream { object_id, size }) => {
                self.read_data_stream(volume, object_id, size, path)
            }
            None => Err(ApfsReadError::ResourceForkMissing {
                path: path.to_string(),
                file_id,
            }),
        }
    }
}

fn expand_block(block: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), InflateError> {
    let Some(first) = block.first() else {
        return Err(InflateError::Truncated);
    };
    if first & 0x0F == DECMPFS_BLOCK_STORED_MARKER {
        let body = &block[1..];
        if body.len() > limit {
            return Err(InflateError::OutputTooLarge { limit });
        }
        out.extend_from_slice(body);
        return Ok(());
    }
    out.extend_from_slice(&zlib_inflate(block, limit)?);
    Ok(())
}

fn expand_resource_fork(
    fork: &[u8],
    size: usize,
    file_id: u64,
    path: &str,
) -> Result<Vec<u8>, ApfsReadError> {
    let malformed = |reason: &'static str| ApfsReadError::ResourceForkMalformed {
        path: path.to_string(),
        file_id,
        reason,
    };
    if fork.len() < RSRC_HEADER_BYTES {
        return Err(malformed("it is shorter than a resource fork header"));
    }
    let data_at = be_u32_at(fork, RSRC_DATA_OFFSET_OFFSET) as usize;
    let data_length = be_u32_at(fork, RSRC_DATA_LENGTH_OFFSET) as usize;
    let data_end = data_at
        .checked_add(data_length)
        .filter(|end| *end <= fork.len())
        .ok_or_else(|| malformed("the resource data leaves the fork"))?;
    if data_length < RSRC_ENTRY_LENGTH_BYTES {
        return Err(malformed("the resource data is shorter than one entry"));
    }

    let table_at = data_at + RSRC_ENTRY_LENGTH_BYTES;
    let entry_length = be_u32_at(fork, data_at) as usize;
    if table_at + entry_length > data_end {
        return Err(malformed("the resource entry leaves the resource data"));
    }
    if entry_length < 4 {
        return Err(malformed(
            "the resource entry is shorter than a block count",
        ));
    }
    let blocks = u32_at(fork, table_at) as usize;
    let table_end = blocks
        .checked_mul(RSRC_BLOCK_ENTRY_BYTES)
        .and_then(|bytes| table_at.checked_add(4 + bytes))
        .filter(|end| *end <= data_end)
        .ok_or_else(|| malformed("the block table leaves the resource data"))?;

    let mut out = Vec::with_capacity(size);
    for index in 0..blocks {
        let entry = table_at + 4 + index * RSRC_BLOCK_ENTRY_BYTES;
        let block_at = table_at + u32_at(fork, entry) as usize;
        let block_length = u32_at(fork, entry + 4) as usize;
        let block_end = block_at
            .checked_add(block_length)
            .filter(|end| *end >= table_end && *end <= data_end)
            .ok_or_else(|| malformed("a compressed block leaves the resource data"))?;
        let remaining = size - out.len().min(size);
        expand_block(
            &fork[block_at..block_end],
            remaining.min(DECMPFS_BLOCK_BYTES),
            &mut out,
        )
        .map_err(|source| ApfsReadError::CompressedStreamBroken {
            path: path.to_string(),
            file_id,
            block: index,
            source,
        })?;
    }
    Ok(out)
}

fn expand_lzvn_block(block: &[u8], limit: usize, out: &mut Vec<u8>) -> Result<(), LzvnError> {
    let Some(first) = block.first() else {
        return Err(LzvnError::Truncated { at: 0 });
    };
    if *first == DECMPFS_LZVN_STORED_MARKER {
        let body = &block[1..];
        if body.len() > limit {
            return Err(LzvnError::OutputTooLarge { limit });
        }
        out.extend_from_slice(body);
        return Ok(());
    }
    lzvn::decode_onto(block, limit, out)
}

fn expand_lzvn_fork(
    fork: &[u8],
    size: usize,
    file_id: u64,
    path: &str,
) -> Result<Vec<u8>, ApfsReadError> {
    let malformed = |reason: &'static str| ApfsReadError::ResourceForkMalformed {
        path: path.to_string(),
        file_id,
        reason,
    };
    if fork.len() < LZVN_TABLE_ENTRY_BYTES {
        return Err(malformed("it is shorter than one block table entry"));
    }
    let table_bytes = u32_at(fork, 0) as usize;
    if table_bytes < 2 * LZVN_TABLE_ENTRY_BYTES
        || !table_bytes.is_multiple_of(LZVN_TABLE_ENTRY_BYTES)
        || table_bytes > fork.len()
    {
        return Err(malformed(
            "the block table length is not a whole table inside the attribute",
        ));
    }
    let blocks = table_bytes / LZVN_TABLE_ENTRY_BYTES - 1;

    let mut out = Vec::with_capacity(size);
    for index in 0..blocks {
        let start = u32_at(fork, index * LZVN_TABLE_ENTRY_BYTES) as usize;
        let end = u32_at(fork, (index + 1) * LZVN_TABLE_ENTRY_BYTES) as usize;
        if start < table_bytes || end < start || end > fork.len() {
            return Err(malformed("a block leaves the attribute"));
        }
        let remaining = size - out.len().min(size);
        expand_lzvn_block(
            &fork[start..end],
            remaining.min(DECMPFS_BLOCK_BYTES),
            &mut out,
        )
        .map_err(|source| ApfsReadError::LzvnStreamBroken {
            path: path.to_string(),
            file_id,
            block: index,
            source,
        })?;
    }
    Ok(out)
}

fn be_u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    Truncated,
    NotZlib { header: u16 },
    PresetDictionary,
    ReservedBlockType,
    StoredLengthMismatch { len: u16, nlen: u16 },
    OversubscribedCode { what: &'static str },
    IncompleteCode { what: &'static str },
    UnknownCode { what: &'static str },
    DistanceTooFar { distance: usize, produced: usize },
    OutputTooLarge { limit: usize },
    ChecksumMismatch { expected: u32, actual: u32 },
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the stream ends inside a block"),
            Self::NotZlib { header } => {
                write!(f, "{header:#06x} is not a zlib header")
            }
            Self::PresetDictionary => f.write_str("the zlib header announces a preset dictionary"),
            Self::ReservedBlockType => f.write_str("a block announces the reserved block type"),
            Self::StoredLengthMismatch { len, nlen } => {
                write!(f, "stored block length {len} does not complement {nlen}")
            }
            Self::OversubscribedCode { what } => {
                write!(
                    f,
                    "the {what} code assigns more codes than its lengths allow"
                )
            }
            Self::IncompleteCode { what } => {
                write!(f, "the {what} code leaves bit patterns unassigned")
            }
            Self::UnknownCode { what } => {
                write!(f, "a symbol read from the {what} code is not in it")
            }
            Self::DistanceTooFar { distance, produced } => write!(
                f,
                "a match reaches {distance} bytes back through {produced} bytes of output"
            ),
            Self::OutputTooLarge { limit } => {
                write!(f, "the stream decodes to more than {limit} bytes")
            }
            Self::ChecksumMismatch { expected, actual } => write!(
                f,
                "the Adler-32 trailer is {expected:#010x} but the decoded bytes give {actual:#010x}"
            ),
        }
    }
}

impl std::error::Error for InflateError {}

const MAX_CODE_BITS: usize = 15;

const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

struct BitReader<'a> {
    bytes: &'a [u8],
    bit: usize,
}

impl<'a> BitReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, bit: 0 }
    }

    fn take(&mut self, count: u32) -> Result<u32, InflateError> {
        let mut value = 0u32;
        for shift in 0..count {
            let byte = *self
                .bytes
                .get(self.bit >> 3)
                .ok_or(InflateError::Truncated)?;
            value |= u32::from((byte >> (self.bit & 7)) & 1) << shift;
            self.bit += 1;
        }
        Ok(value)
    }

    fn align_to_byte(&mut self) {
        self.bit = self.bit.next_multiple_of(8);
    }

    fn byte_index(&self) -> usize {
        self.bit >> 3
    }

    fn skip_bytes(&mut self, count: usize) {
        self.bit += count * 8;
    }
}

#[derive(Debug)]
struct Huffman {
    counts: [u16; MAX_CODE_BITS + 1],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(
        lengths: &[u8],
        what: &'static str,
        allow_incomplete: bool,
    ) -> Result<Self, InflateError> {
        let mut counts = [0u16; MAX_CODE_BITS + 1];
        for length in lengths {
            if *length as usize > MAX_CODE_BITS {
                return Err(InflateError::OversubscribedCode { what });
            }
            counts[*length as usize] += 1;
        }
        let coded = lengths.len() - counts[0] as usize;
        counts[0] = 0;

        let mut spare = 1i32;
        for count in &counts[1..=MAX_CODE_BITS] {
            spare = (spare << 1) - i32::from(*count);
            if spare < 0 {
                return Err(InflateError::OversubscribedCode { what });
            }
        }
        if spare > 0 && !(allow_incomplete && coded <= 1) {
            return Err(InflateError::IncompleteCode { what });
        }

        let mut offsets = [0u16; MAX_CODE_BITS + 2];
        for length in 1..=MAX_CODE_BITS {
            offsets[length + 1] = offsets[length] + counts[length];
        }
        let mut symbols = vec![0u16; coded];
        for (symbol, length) in lengths.iter().enumerate() {
            if *length != 0 {
                symbols[offsets[*length as usize] as usize] = symbol as u16;
                offsets[*length as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, reader: &mut BitReader, what: &'static str) -> Result<u16, InflateError> {
        let mut code = 0i32;
        let mut first = 0i32;
        let mut index = 0i32;
        for length in 1..=MAX_CODE_BITS {
            code |= reader.take(1)? as i32;
            let count = i32::from(self.counts[length]);
            if code - first < count {
                return Ok(self.symbols[(index + code - first) as usize]);
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        Err(InflateError::UnknownCode { what })
    }
}

fn zlib_inflate(stream: &[u8], limit: usize) -> Result<Vec<u8>, InflateError> {
    if stream.len() < 6 {
        return Err(InflateError::Truncated);
    }
    let header = u16::from_be_bytes([stream[0], stream[1]]);
    if stream[0] & 0x0F != 8 || !header.is_multiple_of(31) {
        return Err(InflateError::NotZlib { header });
    }
    if stream[1] & 0x20 != 0 {
        return Err(InflateError::PresetDictionary);
    }
    let (out, consumed) = inflate(&stream[2..], limit)?;
    let trailer_at = 2 + consumed;
    let trailer = stream
        .get(trailer_at..trailer_at + 4)
        .ok_or(InflateError::Truncated)?;
    let expected = u32::from_be_bytes(trailer.try_into().expect("four trailer bytes"));
    let actual = adler32(&out);
    if actual != expected {
        return Err(InflateError::ChecksumMismatch { expected, actual });
    }
    Ok(out)
}

fn inflate(stream: &[u8], limit: usize) -> Result<(Vec<u8>, usize), InflateError> {
    let mut reader = BitReader::new(stream);
    let mut out = Vec::new();
    loop {
        let final_block = reader.take(1)? == 1;
        match reader.take(2)? {
            0 => inflate_stored_block(&mut reader, stream, limit, &mut out)?,
            1 => {
                let (literals, distances) = fixed_codes()?;
                inflate_coded_block(&mut reader, &literals, &distances, limit, &mut out)?;
            }
            2 => {
                let (literals, distances) = dynamic_codes(&mut reader)?;
                inflate_coded_block(&mut reader, &literals, &distances, limit, &mut out)?;
            }
            _ => return Err(InflateError::ReservedBlockType),
        }
        if final_block {
            reader.align_to_byte();
            return Ok((out, reader.byte_index()));
        }
    }
}

fn inflate_stored_block(
    reader: &mut BitReader,
    stream: &[u8],
    limit: usize,
    out: &mut Vec<u8>,
) -> Result<(), InflateError> {
    reader.align_to_byte();
    let at = reader.byte_index();
    let head = stream.get(at..at + 4).ok_or(InflateError::Truncated)?;
    let len = u16::from_le_bytes([head[0], head[1]]);
    let nlen = u16::from_le_bytes([head[2], head[3]]);
    if nlen != !len {
        return Err(InflateError::StoredLengthMismatch { len, nlen });
    }
    let body = stream
        .get(at + 4..at + 4 + len as usize)
        .ok_or(InflateError::Truncated)?;
    if out.len() + body.len() > limit {
        return Err(InflateError::OutputTooLarge { limit });
    }
    out.extend_from_slice(body);
    reader.skip_bytes(4 + len as usize);
    Ok(())
}

fn inflate_coded_block(
    reader: &mut BitReader,
    literals: &Huffman,
    distances: &Huffman,
    limit: usize,
    out: &mut Vec<u8>,
) -> Result<(), InflateError> {
    loop {
        let symbol = literals.decode(reader, "literal and length")? as usize;
        if symbol == 256 {
            return Ok(());
        }
        if symbol < 256 {
            if out.len() >= limit {
                return Err(InflateError::OutputTooLarge { limit });
            }
            out.push(symbol as u8);
            continue;
        }
        let length_symbol = symbol - 257;
        if length_symbol >= LENGTH_BASE.len() {
            return Err(InflateError::UnknownCode {
                what: "literal and length",
            });
        }
        let length = LENGTH_BASE[length_symbol] as usize
            + reader.take(LENGTH_EXTRA[length_symbol])? as usize;

        let distance_symbol = distances.decode(reader, "distance")? as usize;
        if distance_symbol >= DISTANCE_BASE.len() {
            return Err(InflateError::UnknownCode { what: "distance" });
        }
        let distance = DISTANCE_BASE[distance_symbol] as usize
            + reader.take(DISTANCE_EXTRA[distance_symbol])? as usize;
        if distance == 0 || distance > out.len() {
            return Err(InflateError::DistanceTooFar {
                distance,
                produced: out.len(),
            });
        }
        if out.len() + length > limit {
            return Err(InflateError::OutputTooLarge { limit });
        }
        let start = out.len() - distance;
        for offset in 0..length {
            let byte = out[start + offset];
            out.push(byte);
        }
    }
}

fn fixed_codes() -> Result<(Huffman, Huffman), InflateError> {
    let mut literal_lengths = [0u8; 288];
    for (symbol, length) in literal_lengths.iter_mut().enumerate() {
        *length = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let literals = Huffman::new(&literal_lengths, "literal and length", false)?;
    let distances = Huffman::new(&[5u8; 32], "distance", false)?;
    Ok((literals, distances))
}

fn dynamic_codes(reader: &mut BitReader) -> Result<(Huffman, Huffman), InflateError> {
    let literal_count = reader.take(5)? as usize + 257;
    let distance_count = reader.take(5)? as usize + 1;
    let code_length_count = reader.take(4)? as usize + 4;

    let mut code_lengths = [0u8; CODE_LENGTH_ORDER.len()];
    for index in 0..code_length_count {
        code_lengths[CODE_LENGTH_ORDER[index]] = reader.take(3)? as u8;
    }
    let code_length_code = Huffman::new(&code_lengths, "code length", false)?;

    let mut lengths = vec![0u8; literal_count + distance_count];
    let mut at = 0usize;
    while at < lengths.len() {
        let symbol = code_length_code.decode(reader, "code length")?;
        let (repeat, value) = match symbol {
            0..=15 => {
                lengths[at] = symbol as u8;
                at += 1;
                continue;
            }
            16 => {
                if at == 0 {
                    return Err(InflateError::UnknownCode {
                        what: "code length",
                    });
                }
                (3 + reader.take(2)? as usize, lengths[at - 1])
            }
            17 => (3 + reader.take(3)? as usize, 0),
            18 => (11 + reader.take(7)? as usize, 0),
            _ => {
                return Err(InflateError::UnknownCode {
                    what: "code length",
                });
            }
        };
        if at + repeat > lengths.len() {
            return Err(InflateError::OversubscribedCode {
                what: "code length",
            });
        }
        lengths[at..at + repeat].fill(value);
        at += repeat;
    }

    let literals = Huffman::new(&lengths[..literal_count], "literal and length", false)?;
    let distances = Huffman::new(&lengths[literal_count..], "distance", true)?;
    Ok((literals, distances))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asr_server::deflate::{DeflateError, zlib_compress};
    use crate::asr_server::digest::ChecksumType;

    const RAMDISK_IMAGE_ENV: &str = "APPLEUTILS_RAMDISK_IMAGE";
    const FDR_TRUST_OBJECT_PATH: &str = "/System/Library/FDR/fdrtrustobject";
    const FDR_TRUST_OBJECT_BYTES: usize = 9183;
    const FDR_TRUST_OBJECT_SHA256: &str =
        "6da365cf2e3b397770dbd736cdd1675efc4634e6ef4c136753a632abdb0c94d8";

    #[test]
    fn the_geometry_probe_reads_a_container_superblock_out_of_block_zero() {
        let mut block = vec![0u8; 4096];
        block[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&4096u32.to_le_bytes());
        block[0x28..0x30].copy_from_slice(&32_115_712u64.to_le_bytes());
        assert_eq!(
            container_geometry_of(&block).expect("a container superblock"),
            (4096, 32_115_712)
        );
    }

    #[test]
    fn the_geometry_probe_refuses_a_block_that_is_not_a_container() {
        let block = vec![0u8; 4096];
        assert!(matches!(
            container_geometry_of(&block),
            Err(ApfsReadError::NotAContainer { observed: 0 })
        ));
    }

    #[test]
    fn the_geometry_probe_refuses_a_block_size_apfs_does_not_use() {
        let mut block = vec![0u8; 4096];
        block[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&3000u32.to_le_bytes());
        block[0x28..0x30].copy_from_slice(&16u64.to_le_bytes());
        assert!(matches!(
            container_geometry_of(&block),
            Err(ApfsReadError::UnsupportedBlockSize { block_size: 3000 })
        ));
    }

    #[test]
    fn the_geometry_probe_refuses_a_block_too_short_to_carry_the_fields() {
        assert!(matches!(
            container_geometry_of(&[0u8; 16]),
            Err(ApfsReadError::ImageTooSmall { .. })
        ));
    }

    #[test]
    fn a_decmpfs_header_yields_its_type_and_decoded_size() {
        let mut header = vec![0u8; DECMPFS_HEADER_BYTES];
        header[0..4].copy_from_slice(&DECMPFS_MAGIC.to_le_bytes());
        header[DECMPFS_TYPE_OFFSET..DECMPFS_TYPE_OFFSET + 4].copy_from_slice(&14u32.to_le_bytes());
        header[DECMPFS_SIZE_OFFSET..DECMPFS_SIZE_OFFSET + 8]
            .copy_from_slice(&573_440u64.to_le_bytes());
        assert_eq!(
            decmpfs_header_fields(
                &header,
                10776,
                "/System/Library/dyld/dyld_shared_cache_arm64e"
            )
            .expect("a decmpfs header"),
            (14, 573_440)
        );
    }

    #[test]
    fn a_decmpfs_header_that_is_not_one_is_refused_rather_than_read_through() {
        let header = vec![0u8; DECMPFS_HEADER_BYTES];
        assert!(matches!(
            decmpfs_header_fields(&header, 1, "/file"),
            Err(ApfsReadError::CompressionHeaderBadMagic { observed: 0, .. })
        ));
        assert!(matches!(
            decmpfs_header_fields(&[0u8; 4], 1, "/file"),
            Err(ApfsReadError::CompressionHeaderTruncated { length: 4, .. })
        ));
    }

    #[test]
    fn a_sparse_region_is_written_as_the_zeroes_it_reads_as() {
        let mut buffer = vec![0xAAu8; 8];
        let mut out = Vec::new();
        write_zeroes(&mut out, 21, &mut buffer).expect("zeroes are written");
        assert_eq!(out, vec![0u8; 21], "every byte of the hole is written");
    }

    #[test]
    fn a_hole_of_no_bytes_writes_nothing() {
        let mut buffer = vec![0u8; 8];
        let mut out = Vec::new();
        write_zeroes(&mut out, 0, &mut buffer).expect("nothing to write");
        assert!(out.is_empty());
    }

    #[test]
    fn a_destination_that_refuses_the_bytes_is_reported() {
        struct Refuses;
        impl Write for Refuses {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("no room"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut buffer = vec![0u8; 8];
        let error =
            write_zeroes(&mut Refuses, 4, &mut buffer).expect_err("a refused write is not success");
        assert!(matches!(error, ApfsReadError::Output { .. }), "{error}");
    }

    #[test]
    fn a_volume_selection_names_itself_the_way_an_error_has_to_read() {
        assert_eq!(
            VolumeChoice::Named("Macintosh HD".to_string()).to_string(),
            "the volume named \"Macintosh HD\""
        );
        assert_eq!(
            VolumeChoice::Role(1).to_string(),
            "the volume with role 0x1"
        );
        assert_eq!(VolumeChoice::Index(4).to_string(), "the volume at index 4");
    }

    #[test]
    fn an_empty_candidate_list_says_so_rather_than_reading_as_a_name() {
        assert_eq!(describe_list(&[]), "none");
        assert_eq!(
            describe_list(&["Macintosh HD".to_string(), "Data".to_string()]),
            "\"Macintosh HD\", \"Data\""
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn ramdisk_path() -> Option<std::path::PathBuf> {
        std::env::var_os(RAMDISK_IMAGE_ENV).map(std::path::PathBuf::from)
    }

    fn ramdisk() -> Option<Vec<u8>> {
        let path = ramdisk_path()?;
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("{} is present but unreadable: {error}", path.display()),
        }
    }

    #[test]
    fn the_restore_ramdisk_yields_the_fdr_trust_object_a_mount_reads() {
        let Some(image) = ramdisk() else {
            eprintln!("skipped: set {RAMDISK_IMAGE_ENV} to a restore ramdisk APFS image");
            return;
        };
        let bytes = read_file_from_container(&image, FDR_TRUST_OBJECT_PATH)
            .expect("the ramdisk holds the FDR trust object");
        assert_eq!(bytes.len(), FDR_TRUST_OBJECT_BYTES, "trust object length");
        assert_eq!(
            hex(&ChecksumType::Sha256.digest(&bytes)),
            FDR_TRUST_OBJECT_SHA256,
            "trust object digest"
        );
    }

    #[test]
    fn a_path_the_ramdisk_does_not_hold_names_the_component_that_was_missing() {
        let Some(image) = ramdisk() else {
            eprintln!("skipped: set {RAMDISK_IMAGE_ENV} to a restore ramdisk APFS image");
            return;
        };
        let error = read_file_from_container(&image, "/System/Library/FDR/nosuchfile")
            .expect_err("the ramdisk holds no such file");
        match error {
            ApfsReadError::ComponentNotFound {
                ref component,
                ref volume,
                ..
            } => {
                assert_eq!(component, "nosuchfile");
                assert_eq!(volume, "ramdisk");
            }
            other => panic!("expected a missing component, got {other}"),
        }
    }

    #[test]
    fn a_directory_in_the_ramdisk_is_not_a_regular_file() {
        let Some(image) = ramdisk() else {
            eprintln!("skipped: set {RAMDISK_IMAGE_ENV} to a restore ramdisk APFS image");
            return;
        };
        let error = read_file_from_container(&image, "/System/Library/FDR")
            .expect_err("a directory is not a file");
        match error {
            ApfsReadError::NotARegularFile { mode, .. } => {
                assert_eq!(mode & S_IFMT, 0x4000, "the mode says directory");
            }
            other => panic!("expected a non-regular file, got {other}"),
        }
    }

    #[test]
    fn a_component_that_is_not_a_directory_stops_the_walk() {
        let Some(image) = ramdisk() else {
            eprintln!("skipped: set {RAMDISK_IMAGE_ENV} to a restore ramdisk APFS image");
            return;
        };
        let error = read_file_from_container(&image, "/System/Library/FDR/fdrtrustobject/more")
            .expect_err("a file holds no entries");
        match error {
            ApfsReadError::NotADirectory {
                ref component,
                dirent_type,
                ..
            } => {
                assert_eq!(component, "fdrtrustobject");
                assert_eq!(dirent_type, 8, "the entry type says regular file");
            }
            other => panic!("expected a non-directory component, got {other}"),
        }
    }

    #[test]
    fn a_relative_path_is_refused_before_any_block_is_read() {
        let error = read_file_from_container(&[], "System/Library/FDR/fdrtrustobject")
            .expect_err("a relative path names no file in a container");
        assert!(matches!(error, ApfsReadError::PathNotAbsolute { .. }));
    }

    #[test]
    fn a_path_that_walks_upwards_is_refused() {
        let error = read_file_from_container(&[], "/System/../etc/passwd")
            .expect_err("this reader does not follow parent components");
        assert!(matches!(error, ApfsReadError::PathLeavesRoot { .. }));
    }

    #[test]
    fn the_root_itself_names_no_file() {
        let error = read_file_from_container(&[], "/").expect_err("the root is not a file to read");
        assert!(matches!(error, ApfsReadError::PathNamesNoFile { .. }));
    }

    #[test]
    fn a_dot_component_is_walked_through_rather_than_looked_up() {
        assert_eq!(
            path_components("/System/./Library/FDR/fdrtrustobject").expect("a usable path"),
            ["System", "Library", "FDR", "fdrtrustobject"]
        );
    }

    #[test]
    fn an_image_shorter_than_a_superblock_probe_is_refused() {
        let error = read_file_from_container(&[0u8; 512], "/file")
            .expect_err("half a block is not a container");
        assert!(matches!(
            error,
            ApfsReadError::ImageTooSmall {
                length: 512,
                needed: PROBE_BYTES
            }
        ));
    }

    #[test]
    fn an_image_without_the_container_magic_is_refused() {
        let error = read_file_from_container(&[0u8; PROBE_BYTES], "/file")
            .expect_err("a blank block is not a container");
        assert!(matches!(
            error,
            ApfsReadError::NotAContainer { observed: 0 }
        ));
    }

    #[test]
    fn an_image_shorter_than_the_container_it_describes_is_refused() {
        let mut image = vec![0u8; PROBE_BYTES];
        image[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        image[NXSB_BLOCK_SIZE_OFFSET..NXSB_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&4096u32.to_le_bytes());
        image[NXSB_BLOCK_COUNT_OFFSET..NXSB_BLOCK_COUNT_OFFSET + 8]
            .copy_from_slice(&64u64.to_le_bytes());
        let error = read_file_from_container(&image, "/file")
            .expect_err("one block is not sixty four blocks");
        assert_eq!(
            error,
            ApfsReadError::ImageShorterThanContainer {
                image_bytes: 4096,
                container_bytes: 64 * 4096,
            }
        );
    }

    #[test]
    fn a_container_naming_an_unusable_block_size_is_refused() {
        let mut image = vec![0u8; PROBE_BYTES];
        image[0x20..0x24].copy_from_slice(&NX_MAGIC.to_le_bytes());
        image[NXSB_BLOCK_SIZE_OFFSET..NXSB_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&3000u32.to_le_bytes());
        let error =
            read_file_from_container(&image, "/file").expect_err("3000 is not a block size");
        assert_eq!(
            error,
            ApfsReadError::UnsupportedBlockSize { block_size: 3000 }
        );
    }

    const APPLE_COMPRESSED_INODE: [u8; 116] = [
        0xbf, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x12, 0x79, 0x9a, 0x27, 0xa2, 0xa7, 0x18, 0x00, 0x12, 0x79, 0x9a, 0x27, 0xa2,
        0xa7, 0x18, 0xc3, 0x57, 0x9e, 0x38, 0x99, 0x86, 0xb1, 0x18, 0x00, 0x12, 0x79, 0x9a, 0x27,
        0xa2, 0xa7, 0x18, 0x00, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0xdf, 0x23, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x04, 0x02, 0x0f, 0x00, 0x66, 0x64, 0x72, 0x74, 0x72,
        0x75, 0x73, 0x74, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x00, 0x00,
    ];

    #[test]
    fn apples_own_compressed_inode_carries_a_name_field_and_no_data_stream() {
        assert_eq!(
            u16_at(&APPLE_COMPRESSED_INODE, INODE_MODE_OFFSET) & S_IFMT,
            S_IFREG,
            "the mode says regular file"
        );
        assert_eq!(
            u32_at(&APPLE_COMPRESSED_INODE, INODE_BSD_FLAGS_OFFSET) & UF_COMPRESSED,
            UF_COMPRESSED,
            "the BSD flags say compressed"
        );
        assert_eq!(
            inode_data_stream(&APPLE_COMPRESSED_INODE),
            Ok(None),
            "a compressed file has no data stream"
        );
    }

    fn inode_with_fields(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut value = vec![0u8; INODE_XFIELDS_OFFSET];
        value[INODE_MODE_OFFSET..INODE_MODE_OFFSET + 2].copy_from_slice(&S_IFREG.to_le_bytes());
        value.extend_from_slice(&(fields.len() as u16).to_le_bytes());
        let used: usize = fields
            .iter()
            .map(|(_, data)| data.len().next_multiple_of(XFIELD_DATA_ALIGNMENT))
            .sum();
        value.extend_from_slice(&(used as u16).to_le_bytes());
        for (field_type, data) in fields {
            value.push(*field_type);
            value.push(0);
            value.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        for (_, data) in fields {
            value.extend_from_slice(data);
            let padding = data.len().next_multiple_of(XFIELD_DATA_ALIGNMENT) - data.len();
            value.extend(std::iter::repeat_n(0u8, padding));
        }
        value
    }

    #[test]
    fn the_data_stream_field_is_found_behind_fields_of_odd_lengths() {
        let mut dstream = vec![0u8; DSTREAM_BYTES];
        dstream[..8].copy_from_slice(&9183u64.to_le_bytes());
        dstream[DSTREAM_DEFAULT_CRYPTO_ID_OFFSET..DSTREAM_DEFAULT_CRYPTO_ID_OFFSET + 8]
            .copy_from_slice(&4u64.to_le_bytes());
        let inode = inode_with_fields(&[
            (4, b"fdrtrustobject\0".to_vec()),
            (1, vec![0xAA; 3]),
            (INO_EXT_TYPE_DSTREAM, dstream),
        ]);
        let stream = inode_data_stream(&inode)
            .expect("the fields walk")
            .expect("a data stream field");
        assert_eq!(stream.size, 9183);
        assert_eq!(stream.default_crypto_id, 4);
    }

    #[test]
    fn an_extended_field_reaching_past_the_record_is_refused() {
        let mut inode = inode_with_fields(&[(INO_EXT_TYPE_DSTREAM, vec![0u8; DSTREAM_BYTES])]);
        inode.truncate(inode.len() - 8);
        assert_eq!(
            inode_data_stream(&inode),
            Err("an extended field's data leaves the inode record")
        );
    }

    #[test]
    fn a_data_stream_field_too_short_to_be_one_is_refused() {
        let inode = inode_with_fields(&[(INO_EXT_TYPE_DSTREAM, vec![0u8; 8])]);
        assert_eq!(
            inode_data_stream(&inode),
            Err("the data stream extended field is shorter than a data stream")
        );
    }

    fn resource_fork(blocks: &[Vec<u8>]) -> Vec<u8> {
        let table_bytes = 4 + blocks.len() * RSRC_BLOCK_ENTRY_BYTES;
        let mut table = Vec::new();
        table.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
        let mut at = table_bytes;
        for block in blocks {
            table.extend_from_slice(&(at as u32).to_le_bytes());
            table.extend_from_slice(&(block.len() as u32).to_le_bytes());
            at += block.len();
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(at as u32).to_be_bytes());
        data.extend_from_slice(&table);
        for block in blocks {
            data.extend_from_slice(block);
        }

        let data_at = RSRC_HEADER_BYTES + 0xF0;
        let mut fork = Vec::new();
        fork.extend_from_slice(&(data_at as u32).to_be_bytes());
        fork.extend_from_slice(&((data_at + data.len()) as u32).to_be_bytes());
        fork.extend_from_slice(&(data.len() as u32).to_be_bytes());
        fork.extend_from_slice(&0x32u32.to_be_bytes());
        fork.resize(data_at, 0);
        fork.extend_from_slice(&data);
        fork
    }

    #[test]
    fn a_resource_fork_of_several_blocks_reassembles_in_order() {
        let first = b"the first block of a compressed file".to_vec();
        let second = b"the second block of the same file".to_vec();
        let fork = resource_fork(&[zlib_compress(&first), zlib_compress(&second)]);
        let size = first.len() + second.len();
        let out = expand_resource_fork(&fork, size, 196, "/a/file").expect("the fork expands");
        assert_eq!(out, [first, second].concat());
    }

    #[test]
    fn a_stored_block_in_a_resource_fork_is_taken_as_it_stands() {
        let body = b"stored, not compressed".to_vec();
        let mut block = vec![DECMPFS_BLOCK_STORED_MARKER];
        block.extend_from_slice(&body);
        let fork = resource_fork(&[block]);
        let out =
            expand_resource_fork(&fork, body.len(), 196, "/a/file").expect("the fork expands");
        assert_eq!(out, body);
    }

    #[test]
    fn a_block_reserving_more_room_than_its_stream_uses_still_finds_its_trailer() {
        let body = b"a stream with room to spare after it".to_vec();
        let mut block = zlib_compress(&body);
        block.extend_from_slice(&[0xA5; 77]);
        let fork = resource_fork(&[block]);
        let out =
            expand_resource_fork(&fork, body.len(), 196, "/a/file").expect("the fork expands");
        assert_eq!(out, body);
    }

    #[test]
    fn a_resource_fork_whose_block_leaves_the_data_is_refused() {
        let mut fork = resource_fork(&[zlib_compress(b"a block")]);
        let data_at = RSRC_HEADER_BYTES + 0xF0;
        let table_at = data_at + RSRC_ENTRY_LENGTH_BYTES;
        fork[table_at + 8..table_at + 12].copy_from_slice(&0xFFFFu32.to_le_bytes());
        let error =
            expand_resource_fork(&fork, 7, 196, "/a/file").expect_err("the block leaves the data");
        assert!(matches!(
            error,
            ApfsReadError::ResourceForkMalformed {
                reason: "a compressed block leaves the resource data",
                ..
            }
        ));
    }

    #[test]
    fn a_resource_fork_shorter_than_its_header_is_refused() {
        let error = expand_resource_fork(&[0u8; 8], 0, 196, "/a/file")
            .expect_err("eight bytes are not a resource fork");
        assert!(matches!(
            error,
            ApfsReadError::ResourceForkMalformed {
                reason: "it is shorter than a resource fork header",
                ..
            }
        ));
    }

    const MODULE_MAP_FORK: [u8; 186] = [
        0x08, 0x00, 0x00, 0x00, 0xba, 0x00, 0x00, 0x00, 0xe0, 0x29, 0x66, 0x72, 0x61, 0x6d, 0x65,
        0x77, 0x6f, 0x72, 0x6b, 0x20, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x65, 0x20, 0x43, 0x6f, 0x72,
        0x65, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x20, 0x5b, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5d,
        0x20, 0x7b, 0x0a, 0x20, 0x20, 0x75, 0x6d, 0x62, 0x72, 0x65, 0x6c, 0x6c, 0x61, 0x20, 0x68,
        0x65, 0x61, 0x64, 0x65, 0x72, 0x20, 0x22, 0x30, 0x28, 0xc0, 0x20, 0x2e, 0x68, 0x22, 0xea,
        0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x2a, 0x0a, 0x20, 0x28, 0x49, 0xc8, 0x16, 0x2a,
        0x20, 0x7b, 0xf5, 0x80, 0x18, 0x20, 0x7d, 0x18, 0x26, 0xe5, 0x6c, 0x69, 0x63, 0x69, 0x74,
        0x30, 0x6d, 0xe9, 0x49, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x42, 0x75, 0x00, 0x07, 0xc8,
        0x6b, 0x69, 0x6e, 0x73, 0xf1, 0x08, 0x01, 0x30, 0x66, 0x38, 0x21, 0xf5, 0x18, 0x6d, 0x08,
        0x01, 0x38, 0x71, 0xf1, 0xe4, 0x7d, 0x0a, 0x7d, 0x0a, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1b, 0xe0, 0x09, 0x6e, 0x63, 0x6c, 0x75, 0x64, 0x65, 0x20, 0x3c, 0x54, 0x61,
        0x72, 0x67, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c,
        0x00, 0xad, 0x68, 0x21, 0x3e, 0xf4,
    ];

    const MODULE_MAP_PLAIN: &[u8] = b"framework module CoreImage [system] {\n  \
umbrella header \"CoreImage.h\"\n  export *\n  module * { export * }\n  \n  \
explicit module CIFilterBuiltins {\n      header \"CIFilterBuiltins.h\"\n      \
export *\n  }\n}\n";

    fn lzvn_fork(blocks: &[Vec<u8>]) -> Vec<u8> {
        let table_bytes = (blocks.len() + 1) * LZVN_TABLE_ENTRY_BYTES;
        let mut fork = Vec::new();
        let mut at = table_bytes;
        fork.extend_from_slice(&(at as u32).to_le_bytes());
        for block in blocks {
            at += block.len();
            fork.extend_from_slice(&(at as u32).to_le_bytes());
        }
        for block in blocks {
            fork.extend_from_slice(block);
        }
        fork
    }

    fn lzvn_literals(body: &[u8]) -> Vec<u8> {
        assert!((1..=271).contains(&body.len()));
        let mut block = if body.len() < 16 {
            vec![0xE0 | body.len() as u8]
        } else {
            vec![0xE0, (body.len() - 16) as u8]
        };
        block.extend_from_slice(body);
        block.extend_from_slice(&[0x06, 0, 0, 0, 0, 0, 0, 0]);
        block
    }

    #[test]
    fn a_type_8_attribute_apple_wrote_decodes_to_the_file_it_came_from() {
        let out = expand_lzvn_fork(
            &MODULE_MAP_FORK,
            MODULE_MAP_PLAIN.len(),
            8801,
            "/a/module.map",
        )
        .expect("the attribute expands");
        assert_eq!(out, MODULE_MAP_PLAIN);
    }

    #[test]
    fn a_type_8_attribute_of_several_blocks_reassembles_in_order() {
        let first = b"first block".to_vec();
        let second = b"second one".to_vec();
        let fork = lzvn_fork(&[lzvn_literals(&first), lzvn_literals(&second)]);
        let out = expand_lzvn_fork(&fork, first.len() + second.len(), 196, "/a/file")
            .expect("the attribute expands");
        assert_eq!(out, [first, second].concat());
    }

    #[test]
    fn a_stored_block_in_a_type_8_attribute_is_taken_as_it_stands() {
        let body = b"stored, not compressed".to_vec();
        let mut stored = vec![DECMPFS_LZVN_STORED_MARKER];
        stored.extend_from_slice(&body);
        let compressed = b"and this one did compress".to_vec();

        let fork = lzvn_fork(&[stored, lzvn_literals(&compressed)]);
        let out = expand_lzvn_fork(&fork, body.len() + compressed.len(), 196, "/a/file")
            .expect("the attribute expands");
        assert_eq!(out, [body, compressed].concat());
    }

    #[test]
    fn a_type_8_attribute_whose_block_leaves_it_is_refused() {
        let mut fork = lzvn_fork(&[lzvn_literals(b"a block")]);
        fork[4..8].copy_from_slice(&0xFFFFu32.to_le_bytes());
        let error =
            expand_lzvn_fork(&fork, 7, 196, "/a/file").expect_err("the block leaves the attribute");
        assert!(matches!(
            error,
            ApfsReadError::ResourceForkMalformed {
                reason: "a block leaves the attribute",
                ..
            }
        ));
    }

    #[test]
    fn a_type_8_attribute_whose_table_is_not_one_is_refused() {
        for table in [0u32, 4, 7, 0xFFFF] {
            let mut fork = lzvn_fork(&[lzvn_literals(b"a block")]);
            fork[0..4].copy_from_slice(&table.to_le_bytes());
            let error =
                expand_lzvn_fork(&fork, 7, 196, "/a/file").expect_err("the table is not a table");
            assert!(
                matches!(
                    error,
                    ApfsReadError::ResourceForkMalformed {
                        reason: "the block table length is not a whole table inside the attribute",
                        ..
                    }
                ),
                "{table}"
            );
        }
        let error = expand_lzvn_fork(&[0u8; 3], 0, 196, "/a/file")
            .expect_err("three bytes are not a table");
        assert!(matches!(
            error,
            ApfsReadError::ResourceForkMalformed {
                reason: "it is shorter than one block table entry",
                ..
            }
        ));
    }

    #[test]
    fn a_type_8_block_that_does_not_decode_is_named_by_its_index() {
        let fork = lzvn_fork(&[lzvn_literals(b"first"), vec![0x70, 0, 0, 0, 0, 0, 0, 0]]);
        let error =
            expand_lzvn_fork(&fork, 64, 196, "/a/file").expect_err("the second block is reserved");
        assert!(
            matches!(
                error,
                ApfsReadError::LzvnStreamBroken {
                    block: 1,
                    source: LzvnError::ReservedOpcode { opcode: 0x70, .. },
                    ..
                }
            ),
            "{error}"
        );
    }

    #[test]
    fn a_type_8_attribute_cannot_decode_past_its_declared_size() {
        let fork = lzvn_fork(&[lzvn_literals(b"first"), lzvn_literals(b"second")]);
        let error =
            expand_lzvn_fork(&fork, 5, 196, "/a/file").expect_err("the second block has no room");
        assert!(
            matches!(
                error,
                ApfsReadError::LzvnStreamBroken {
                    block: 1,
                    source: LzvnError::OutputTooLarge { limit: 0 },
                    ..
                }
            ),
            "{error}"
        );
    }

    const FIXED_HUFFMAN_ZLIB: [u8; 26] = [
        0x78, 0xda, 0x73, 0x0c, 0x70, 0x0b, 0x56, 0x28, 0x4a, 0x4d, 0x4c, 0x29, 0x56, 0x48, 0x54,
        0x48, 0xcb, 0xcc, 0x49, 0xd5, 0x03, 0x00, 0x35, 0xda, 0x05, 0xc9,
    ];
    const FIXED_HUFFMAN_TEXT: &str = "APFS reads a file.";

    const DYNAMIC_HUFFMAN_ZLIB: [u8; 261] = [
        0x78, 0xda, 0x7d, 0xd4, 0x31, 0x8a, 0xc3, 0x40, 0x0c, 0x85, 0xe1, 0x7e, 0x4f, 0x31, 0x47,
        0xb0, 0xa4, 0xd1, 0x48, 0x3a, 0x8e, 0x21, 0x0e, 0x0e, 0x0c, 0x49, 0xb1, 0xde, 0x90, 0xe3,
        0x2f, 0xa9, 0x9f, 0x9f, 0x5b, 0xf1, 0x17, 0x82, 0x0f, 0x69, 0x3e, 0x9e, 0x5b, 0x5b, 0xda,
        0xfe, 0x9a, 0xb7, 0xdf, 0x76, 0xec, 0x5b, 0x7b, 0xaf, 0xf3, 0xef, 0x3b, 0x59, 0x9f, 0xb7,
        0xb6, 0xb6, 0x63, 0x7d, 0xcc, 0xf6, 0xba, 0xb7, 0x63, 0xfb, 0x1c, 0x3f, 0xf3, 0xdb, 0x0a,
        0xb4, 0x25, 0x45, 0x6b, 0x85, 0x3a, 0x2d, 0x69, 0x6d, 0x50, 0x87, 0x07, 0xad, 0x3b, 0xd4,
        0x23, 0x06, 0xad, 0x1d, 0x6a, 0x2f, 0xa7, 0xf5, 0xc0, 0x5a, 0x3a, 0xad, 0x03, 0xea, 0x6e,
        0x46, 0xeb, 0x84, 0xda, 0x5c, 0x69, 0x5d, 0x50, 0x6b, 0x08, 0xd7, 0x41, 0x4a, 0xa9, 0x0b,
        0x4c, 0xd4, 0x94, 0x85, 0x6b, 0x0a, 0x72, 0x2a, 0xd7, 0x14, 0xe4, 0xac, 0xce, 0x39, 0x05,
        0x3d, 0x73, 0x70, 0x4f, 0x41, 0xd0, 0x48, 0x0e, 0x2a, 0x28, 0x1a, 0x0b, 0x17, 0x15, 0x24,
        0x1d, 0xca, 0x49, 0x05, 0x4d, 0xbd, 0x73, 0x53, 0x41, 0xd4, 0x3e, 0x38, 0xaa, 0x22, 0xaa,
        0x25, 0x47, 0x55, 0x44, 0xd5, 0xba, 0x38, 0xd1, 0x13, 0x54, 0xe1, 0xaa, 0x8a, 0xaa, 0x62,
        0x5c, 0x55, 0x51, 0xd5, 0x39, 0xaa, 0x22, 0x6a, 0x05, 0x47, 0x55, 0x44, 0xcd, 0xe2, 0xa8,
        0x8a, 0xa8, 0x29, 0x1c, 0x55, 0x11, 0x35, 0x8c, 0xa3, 0x2a, 0xa2, 0x0e, 0xe7, 0xa8, 0x86,
        0xa8, 0x1e, 0x1c, 0xd5, 0x10, 0xb5, 0x27, 0x47, 0x35, 0x44, 0xed, 0xcb, 0xc5, 0xe3, 0x45,
        0x54, 0x53, 0x8e, 0x6a, 0x88, 0xaa, 0x9d, 0xab, 0x1a, 0xaa, 0xca, 0xe0, 0xaa, 0x76, 0xa2,
        0xca, 0x51, 0x0d, 0x51, 0x39, 0xa9, 0x21, 0x69, 0x29, 0x27, 0xb5, 0x3a, 0xd9, 0xe4, 0x94,
        0xf4, 0x1f, 0x4d, 0x88, 0x5f, 0xc4,
    ];

    fn dynamic_huffman_text() -> String {
        (0..40u32)
            .map(|index| {
                format!(
                    "line {index} holds the value {} and a tail of text\n",
                    index * 7919 % 1000
                )
            })
            .collect()
    }

    #[test]
    fn a_fixed_huffman_stream_decodes_to_the_text_it_was_made_from() {
        let out = zlib_inflate(&FIXED_HUFFMAN_ZLIB, 4096).expect("the stream inflates");
        assert_eq!(out, FIXED_HUFFMAN_TEXT.as_bytes());
    }

    #[test]
    fn a_dynamic_huffman_stream_decodes_to_the_text_it_was_made_from() {
        let expected = dynamic_huffman_text();
        let out = zlib_inflate(&DYNAMIC_HUFFMAN_ZLIB, 1 << 16).expect("the stream inflates");
        assert_eq!(String::from_utf8(out).expect("text"), expected);
    }

    #[test]
    fn a_stored_zlib_stream_from_the_asr_writer_round_trips() {
        let body: Vec<u8> = (0..70_000u32).map(|index| (index % 251) as u8).collect();
        let stream = zlib_compress(&body);
        assert_eq!(
            zlib_inflate(&stream, body.len()).expect("the stream inflates"),
            body
        );
    }

    #[test]
    fn the_two_inflate_paths_agree_on_a_stored_stream() {
        let body = b"both readers see the same bytes".to_vec();
        let stream = zlib_compress(&body);
        let ours = zlib_inflate(&stream, body.len()).expect("inflates");
        let theirs: Result<Vec<u8>, DeflateError> =
            crate::asr_server::deflate::zlib_decompress(&stream);
        assert_eq!(ours, theirs.expect("the asr reader inflates it"));
    }

    #[test]
    fn a_stream_whose_adler_trailer_is_wrong_is_refused() {
        let mut stream = FIXED_HUFFMAN_ZLIB;
        let last = stream.len() - 1;
        stream[last] ^= 0xFF;
        let error = zlib_inflate(&stream, 4096).expect_err("the trailer is wrong");
        assert!(matches!(error, InflateError::ChecksumMismatch { .. }));
    }

    #[test]
    fn a_stream_that_is_not_zlib_is_refused() {
        let error = zlib_inflate(&[0u8; 16], 4096).expect_err("zeroes are not a zlib header");
        assert!(matches!(error, InflateError::NotZlib { header: 0 }));
    }

    #[test]
    fn a_truncated_stream_is_refused_rather_than_returning_what_it_read() {
        let mut stream = DYNAMIC_HUFFMAN_ZLIB.to_vec();
        stream.truncate(60);
        let error = zlib_inflate(&stream, 1 << 16).expect_err("the stream ends inside its block");
        assert!(matches!(
            error,
            InflateError::Truncated | InflateError::ChecksumMismatch { .. }
        ));
    }

    #[test]
    fn a_stream_that_decodes_past_the_limit_is_refused() {
        let error = zlib_inflate(&DYNAMIC_HUFFMAN_ZLIB, 64).expect_err("the limit is too small");
        assert_eq!(error, InflateError::OutputTooLarge { limit: 64 });
    }

    #[test]
    fn a_huffman_code_that_leaves_patterns_unassigned_is_refused() {
        let mut lengths = [0u8; 8];
        lengths[0] = 1;
        lengths[1] = 3;
        let error = Huffman::new(&lengths, "test", false).expect_err("the code is incomplete");
        assert_eq!(error, InflateError::IncompleteCode { what: "test" });
    }

    #[test]
    fn a_huffman_code_that_assigns_too_many_codes_is_refused() {
        let error =
            Huffman::new(&[1u8; 4], "test", false).expect_err("four one-bit codes do not fit");
        assert_eq!(error, InflateError::OversubscribedCode { what: "test" });
    }

    #[test]
    fn a_single_distance_code_is_accepted_where_a_complete_one_is_not_required() {
        let mut lengths = [0u8; 30];
        lengths[0] = 1;
        assert!(Huffman::new(&lengths, "distance", true).is_ok());
        assert_eq!(
            Huffman::new(&lengths, "distance", false).expect_err("incomplete"),
            InflateError::IncompleteCode { what: "distance" }
        );
    }
}
