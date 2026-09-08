use std::fmt;

pub const SECTOR_BYTES: usize = 512;

// GPT LBAs are in the device's own block units: Apple silicon ANS namespaces are 4096, so a 512-byte reading is eight times off.
pub const APPLE_SILICON_ANS_BLOCK_SIZE: u32 = 4096;

pub const GPT_ENTRY_COUNT: u32 = 128;

pub const GPT_ENTRY_BYTES: u32 = 128;

pub const GPT_ENTRY_ARRAY_BYTES: u64 = (GPT_ENTRY_COUNT * GPT_ENTRY_BYTES) as u64;

pub const fn gpt_entry_array_blocks(block_size: u32) -> u64 {
    GPT_ENTRY_ARRAY_BYTES.div_ceil(block_size as u64)
}

pub const fn gpt_reserved_blocks(block_size: u32) -> u64 {
    1 + gpt_entry_array_blocks(block_size)
}

pub const fn gpt_first_usable_lba(block_size: u32) -> u64 {
    2 + gpt_entry_array_blocks(block_size)
}

pub const fn gpt_min_blocks(block_size: u32) -> u64 {
    gpt_first_usable_lba(block_size) + gpt_reserved_blocks(block_size) + 1
}

pub const GPT_RESERVED_SECTORS: u64 = gpt_reserved_blocks(SECTOR_BYTES as u32);

pub const GPT_FIRST_USABLE_LBA: u64 = gpt_first_usable_lba(SECTOR_BYTES as u32);

pub const GPT_MIN_SECTORS: u64 = gpt_min_blocks(SECTOR_BYTES as u32);

pub const APPLE_APFS_ISC_TYPE_GUID: [u8; 16] = guid(
    0x6964_6961,
    0x6700,
    0x11AA,
    [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC],
);

pub const APPLE_APFS_TYPE_GUID: [u8; 16] = guid(
    0x7C34_57EF,
    0x0000,
    0x11AA,
    [0xAA, 0x11, 0x00, 0x30, 0x65, 0x43, 0xEC, 0xAC],
);

pub const EFI_SYSTEM_PARTITION_TYPE_GUID: [u8; 16] = guid(
    0xC12A_7328,
    0xF81F,
    0x11D2,
    [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
);

pub const LINUX_FILESYSTEM_TYPE_GUID: [u8; 16] = guid(
    0x0FC6_3DAF,
    0x8483,
    0x4772,
    [0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4],
);

pub const GPT_SIGNATURE: [u8; 8] = *b"EFI PART";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPartition {
    pub type_guid: [u8; 16],
    pub unique_guid: [u8; 16],
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    pub name: String,
}

impl GptPartition {
    pub fn byte_range(&self, block_size: u32) -> (u64, u64) {
        let bs = u64::from(block_size);
        (self.first_lba * bs, (self.last_lba + 1) * bs)
    }

    pub fn is_apple_apfs(&self) -> bool {
        self.type_guid == APPLE_APFS_TYPE_GUID
    }

    pub fn is_efi(&self) -> bool {
        self.type_guid == EFI_SYSTEM_PARTITION_TYPE_GUID
    }

    pub fn is_linux(&self) -> bool {
        self.type_guid == LINUX_FILESYSTEM_TYPE_GUID
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptTable {
    pub block_size: u32,
    pub disk_guid: [u8; 16],
    pub partitions: Vec<GptPartition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GptError {
    TooShort { length: usize },
    BadSignature,
    UnsupportedBlockSize { block_size: u32 },
}

impl fmt::Display for GptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { length } => {
                write!(f, "image of {length} bytes is too short for a GPT")
            }
            Self::BadSignature => write!(f, "missing EFI PART GPT signature"),
            Self::UnsupportedBlockSize { block_size } => {
                write!(f, "unsupported GPT block size {block_size}")
            }
        }
    }
}

impl std::error::Error for GptError {}

pub fn parse_gpt(image: &[u8], block_size: u32) -> Result<GptTable, GptError> {
    if block_size < 512 || !block_size.is_power_of_two() {
        return Err(GptError::UnsupportedBlockSize { block_size });
    }
    let header_at = block_size as usize;
    let needed = header_at + 92;
    if image.len() < needed {
        return Err(GptError::TooShort {
            length: image.len(),
        });
    }
    let header = &image[header_at..header_at + 92];
    if header[0..8] != GPT_SIGNATURE {
        return Err(GptError::BadSignature);
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&header[56..72]);
    let part_lba = u64::from_le_bytes(header[72..80].try_into().unwrap());
    let part_count = u32::from_le_bytes(header[80..84].try_into().unwrap()) as usize;
    let part_size = u32::from_le_bytes(header[84..88].try_into().unwrap()) as usize;
    if part_size < 128 {
        return Err(GptError::BadSignature);
    }
    let array_at = (part_lba as usize).saturating_mul(block_size as usize);
    let array_bytes = part_count.saturating_mul(part_size);
    if image.len() < array_at.saturating_add(array_bytes) {
        return Err(GptError::TooShort {
            length: image.len(),
        });
    }
    let mut partitions = Vec::new();
    for index in 0..part_count {
        let at = array_at + index * part_size;
        let entry = &image[at..at + part_size];
        if entry[0..16].iter().all(|b| *b == 0) {
            continue;
        }
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&entry[0..16]);
        let mut unique_guid = [0u8; 16];
        unique_guid.copy_from_slice(&entry[16..32]);
        let first_lba = u64::from_le_bytes(entry[32..40].try_into().unwrap());
        let last_lba = u64::from_le_bytes(entry[40..48].try_into().unwrap());
        let attributes = u64::from_le_bytes(entry[48..56].try_into().unwrap());
        let name = utf16le_z(&entry[56..128.min(part_size)]);
        partitions.push(GptPartition {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
            name,
        });
    }
    Ok(GptTable {
        block_size,
        disk_guid,
        partitions,
    })
}

fn utf16le_z(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

pub const fn guid(data1: u32, data2: u16, data3: u16, tail: [u8; 8]) -> [u8; 16] {
    let d1 = data1.to_le_bytes();
    let d2 = data2.to_le_bytes();
    let d3 = data3.to_le_bytes();
    [
        d1[0], d1[1], d1[2], d1[3], d2[0], d2[1], d3[0], d3[1], tail[0], tail[1], tail[2], tail[3],
        tail[4], tail[5], tail[6], tail[7],
    ]
}

pub const APFS_OBJ_PHYS_BYTES: usize = 32;

pub const NX_MAGIC_OFFSET: usize = 0x20;
pub const NX_BLOCK_SIZE_OFFSET: usize = 0x24;
pub const NX_BLOCK_COUNT_OFFSET: usize = 0x28;
pub const NX_UUID_OFFSET: usize = 0x48;
pub const NX_FLAGS_OFFSET: usize = 0x4F0;

pub const NX_MAGIC: u32 = 0x4253_584E;

pub const NX_PROBE_BLOCK_SIZE: u32 = 0x1000;

pub const NX_FLAG_COMPOSITED: u8 = 1 << 2;

pub const APFS_VOL_ROLE_NONE: u16 = 0x0000;
pub const APFS_VOL_ROLE_SYSTEM: u16 = 0x0001;
pub const APFS_VOL_ROLE_USER: u16 = 0x0002;
pub const APFS_VOL_ROLE_RECOVERY: u16 = 0x0004;
pub const APFS_VOL_ROLE_VM: u16 = 0x0008;
pub const APFS_VOL_ROLE_PREBOOT: u16 = 0x0010;
pub const APFS_VOL_ROLE_INSTALLER: u16 = 0x0020;
pub const APFS_VOL_ROLE_DATA: u16 = 1 << 6;
pub const APFS_VOL_ROLE_BASEBAND: u16 = 2 << 6;
pub const APFS_VOL_ROLE_UPDATE: u16 = 3 << 6;
pub const APFS_VOL_ROLE_XART: u16 = 4 << 6;
pub const APFS_VOL_ROLE_HARDWARE: u16 = 5 << 6;
pub const APFS_VOL_ROLE_BACKUP: u16 = 6 << 6;

pub fn apfs_role_name(role: u16) -> Option<&'static str> {
    Some(match role {
        APFS_VOL_ROLE_NONE => "none",
        APFS_VOL_ROLE_SYSTEM => "System",
        APFS_VOL_ROLE_USER => "User",
        APFS_VOL_ROLE_RECOVERY => "Recovery",
        APFS_VOL_ROLE_VM => "VM",
        APFS_VOL_ROLE_PREBOOT => "Preboot",
        APFS_VOL_ROLE_INSTALLER => "Installer",
        APFS_VOL_ROLE_DATA => "Data",
        APFS_VOL_ROLE_BASEBAND => "Baseband",
        APFS_VOL_ROLE_UPDATE => "Update",
        APFS_VOL_ROLE_XART => "xART",
        APFS_VOL_ROLE_HARDWARE => "Hardware",
        APFS_VOL_ROLE_BACKUP => "Backup",
        _ => return None,
    })
}

pub const APFS_INCOMPAT_SEALED_VOLUME: u64 = 0x20;

pub fn fletcher64(block: &[u8]) -> u64 {
    let (lo, hi) = fletcher64_sums(&block[8..]);
    let c1 = 0xFFFF_FFFF - ((lo + hi) % 0xFFFF_FFFF);
    let c2 = 0xFFFF_FFFF - ((lo + c1) % 0xFFFF_FFFF);
    (c2 << 32) | c1
}

pub fn fletcher64_seal(block: &mut [u8]) {
    let checksum = fletcher64(block);
    block[0..8].copy_from_slice(&checksum.to_le_bytes());
}

pub fn fletcher64_valid(block: &[u8]) -> bool {
    block.len() >= 8 && block.len().is_multiple_of(4) && fletcher64_sums(block).0 == 0
}

fn fletcher64_sums(body: &[u8]) -> (u64, u64) {
    let mut lo: u64 = 0;
    let mut hi: u64 = 0;
    for word in body.chunks_exact(4) {
        lo = (lo + u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64) % 0xFFFF_FFFF;
        hi = (hi + lo) % 0xFFFF_FFFF;
    }
    (lo, hi)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContainerProbe {
    pub block_size: u32,
    pub block_count: u64,
    pub uuid: [u8; 16],
    pub composited: bool,
    pub checksum_valid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainerProbeError {
    TooShort { bytes: usize },
    BadMagic { observed: u32 },
}

impl fmt::Display for ContainerProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { bytes } => write!(f, "block of {bytes} bytes is too short for NXSB"),
            Self::BadMagic { observed } => {
                write!(
                    f,
                    "expected NXSB magic {NX_MAGIC:#010x}, found {observed:#010x}"
                )
            }
        }
    }
}

impl std::error::Error for ContainerProbeError {}

pub fn probe_container(block0: &[u8]) -> Result<ContainerProbe, ContainerProbeError> {
    if block0.len() <= NX_FLAGS_OFFSET {
        return Err(ContainerProbeError::TooShort {
            bytes: block0.len(),
        });
    }
    let magic = le_u32(block0, NX_MAGIC_OFFSET);
    if magic != NX_MAGIC {
        return Err(ContainerProbeError::BadMagic { observed: magic });
    }
    let raw_block_size = le_u32(block0, NX_BLOCK_SIZE_OFFSET);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&block0[NX_UUID_OFFSET..NX_UUID_OFFSET + 16]);
    Ok(ContainerProbe {
        block_size: if raw_block_size == 0 {
            NX_PROBE_BLOCK_SIZE
        } else {
            raw_block_size.min(NX_PROBE_BLOCK_SIZE)
        },
        block_count: le_u64(block0, NX_BLOCK_COUNT_OFFSET),
        uuid,
        composited: block0[NX_FLAGS_OFFSET] & NX_FLAG_COMPOSITED != 0,
        checksum_valid: fletcher64_valid(block0),
    })
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn part_guid(seed: u8) -> [u8; 16] {
        let mut bytes = [seed; 16];
        bytes[0] = 0xA0 | (seed & 0x0F);
        bytes
    }

    #[test]
    fn fletcher64_seal_then_validate_round_trips() {
        let mut block = vec![0u8; 4096];
        for (index, byte) in block.iter_mut().enumerate().skip(8) {
            *byte = (index % 251) as u8;
        }
        assert!(!fletcher64_valid(&block));
        fletcher64_seal(&mut block);
        assert!(fletcher64_valid(&block));

        block[2048] ^= 0x01;
        assert!(!fletcher64_valid(&block));
    }

    #[test]
    fn fletcher64_is_sensitive_to_every_word_position() {
        let base = {
            let mut block = vec![0u8; 4096];
            fletcher64_seal(&mut block);
            block
        };
        assert!(fletcher64_valid(&base));
        for word in [1usize, 7, 512, 1023] {
            let mut block = base.clone();
            block[word * 4] ^= 0x01;
            assert!(
                !fletcher64_valid(&block),
                "flipping word {word} left the block valid"
            );
        }
    }

    fn synthetic_nxsb() -> Vec<u8> {
        let mut block = vec![0u8; 4096];
        block[NX_MAGIC_OFFSET..NX_MAGIC_OFFSET + 4].copy_from_slice(&NX_MAGIC.to_le_bytes());
        block[NX_BLOCK_SIZE_OFFSET..NX_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&4096u32.to_le_bytes());
        block[NX_BLOCK_COUNT_OFFSET..NX_BLOCK_COUNT_OFFSET + 8]
            .copy_from_slice(&16384u64.to_le_bytes());
        block[NX_UUID_OFFSET..NX_UUID_OFFSET + 16].copy_from_slice(&part_guid(0x31));
        fletcher64_seal(&mut block);
        block
    }

    #[test]
    fn probe_reads_the_fields_the_kext_matches_on() {
        let block = synthetic_nxsb();
        let probe = probe_container(&block).expect("probe");
        assert_eq!(probe.block_size, 4096);
        assert_eq!(probe.block_count, 16384);
        assert_eq!(probe.uuid, part_guid(0x31));
        assert!(!probe.composited);
        assert!(probe.checksum_valid);
    }

    #[test]
    fn probe_clamps_block_size_and_reads_the_composited_flag() {
        let mut block = synthetic_nxsb();
        block[NX_BLOCK_SIZE_OFFSET..NX_BLOCK_SIZE_OFFSET + 4]
            .copy_from_slice(&65536u32.to_le_bytes());
        block[NX_FLAGS_OFFSET] |= NX_FLAG_COMPOSITED;
        fletcher64_seal(&mut block);
        let probe = probe_container(&block).expect("probe");
        assert_eq!(probe.block_size, NX_PROBE_BLOCK_SIZE);
        assert!(probe.composited);
    }

    #[test]
    fn a_blank_partition_never_probes_as_a_container() {
        let blank = vec![0u8; 4096];
        assert_eq!(
            probe_container(&blank),
            Err(ContainerProbeError::BadMagic { observed: 0 })
        );
        assert_eq!(
            probe_container(&[0u8; 64]),
            Err(ContainerProbeError::TooShort { bytes: 64 })
        );
    }

    #[test]
    fn volume_role_encoding_matches_the_kext_role_table() {
        assert_eq!(APFS_VOL_ROLE_SYSTEM, 0x0001);
        assert_eq!(APFS_VOL_ROLE_USER, 0x0002);
        assert_eq!(APFS_VOL_ROLE_RECOVERY, 0x0004);
        assert_eq!(APFS_VOL_ROLE_VM, 0x0008);
        assert_eq!(APFS_VOL_ROLE_PREBOOT, 0x0010);
        assert_eq!(APFS_VOL_ROLE_INSTALLER, 0x0020);
        assert_eq!(APFS_VOL_ROLE_XART, 0x0100);
        assert_eq!(APFS_VOL_ROLE_HARDWARE, 0x0140);
        assert_eq!(APFS_VOL_ROLE_XART >> 6, 4);
        assert_eq!(APFS_VOL_ROLE_HARDWARE >> 6, 5);
        assert_eq!(APFS_VOL_ROLE_XART & 0x3F, APFS_VOL_ROLE_NONE);
        assert_eq!(APFS_VOL_ROLE_HARDWARE & 0x3F, APFS_VOL_ROLE_NONE);
    }

    #[test]
    fn type_guids_use_the_mixed_endian_on_disk_encoding() {
        assert_eq!(
            APPLE_APFS_ISC_TYPE_GUID,
            [
                0x61, 0x69, 0x64, 0x69, 0x00, 0x67, 0xAA, 0x11, 0xAA, 0x11, 0x00, 0x30, 0x65, 0x43,
                0xEC, 0xAC,
            ]
        );
        assert_eq!(
            APPLE_APFS_TYPE_GUID,
            [
                0xef, 0x57, 0x34, 0x7c, 0x00, 0x00, 0xaa, 0x11, 0xaa, 0x11, 0x00, 0x30, 0x65, 0x43,
                0xec, 0xac,
            ]
        );
        assert_eq!(
            EFI_SYSTEM_PARTITION_TYPE_GUID,
            [
                0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
                0xC9, 0x3B,
            ]
        );
        assert_eq!(
            LINUX_FILESYSTEM_TYPE_GUID,
            [
                0xAF, 0x3D, 0xC6, 0x0F, 0x83, 0x84, 0x72, 0x47, 0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47,
                0x7D, 0xE4,
            ]
        );
    }
}
