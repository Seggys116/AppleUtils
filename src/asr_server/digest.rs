use crate::crypto::{Sha1, Sha256, Sha512};

pub const SHA1_DIGEST_LEN: usize = 20;

pub const SHA256_DIGEST_LEN: usize = 32;

pub const SHA384_DIGEST_LEN: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumType {
    Sha1,
    Sha256,
}

impl ChecksumType {
    pub const fn wire_value(self) -> i64 {
        match self {
            Self::Sha1 => 0,
            Self::Sha256 => 1,
        }
    }

    pub const fn from_wire(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Sha1),
            1 => Some(Self::Sha256),
            _ => None,
        }
    }

    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => SHA1_DIGEST_LEN,
            Self::Sha256 => SHA256_DIGEST_LEN,
        }
    }

    pub fn hasher(self) -> BlockHasher {
        match self {
            Self::Sha1 => BlockHasher::Sha1(Sha1::new()),
            Self::Sha256 => BlockHasher::Sha256(Sha256::new()),
        }
    }

    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        hasher.update(bytes);
        hasher.finish()
    }
}

#[derive(Clone, Copy)]
pub enum BlockHasher {
    Sha1(Sha1),
    Sha256(Sha256),
}

impl BlockHasher {
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(state) => state.update(bytes),
            Self::Sha256(state) => state.update(bytes),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(state) => state.finish().to_vec(),
            Self::Sha256(state) => state.finish().to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamDigestKind {
    Sha1,
    Sha384,
}

impl StreamDigestKind {
    pub const fn for_expected_hash_len(len: usize) -> Self {
        if len == SHA384_DIGEST_LEN {
            Self::Sha384
        } else {
            Self::Sha1
        }
    }

    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => SHA1_DIGEST_LEN,
            Self::Sha384 => SHA384_DIGEST_LEN,
        }
    }

    pub fn hasher(self) -> StreamHasher {
        match self {
            Self::Sha1 => StreamHasher::Sha1(Sha1::new()),
            Self::Sha384 => StreamHasher::Sha384(Sha512::sha384()),
        }
    }

    pub fn digest(self, bytes: &[u8]) -> Vec<u8> {
        let mut hasher = self.hasher();
        hasher.update(bytes);
        hasher.finish()
    }
}

// Covers the concatenated data bytes only: asr excludes the per-block digests.
#[derive(Clone, Copy)]
pub enum StreamHasher {
    Sha1(Sha1),
    Sha384(Sha512),
}

impl StreamHasher {
    pub fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(state) => state.update(bytes),
            Self::Sha384(state) => state.update(bytes),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha1(state) => state.finish().to_vec(),
            Self::Sha384(state) => state.finish()[..SHA384_DIGEST_LEN].to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_type_wire_values_match_the_values_asr_accepts() {
        assert_eq!(ChecksumType::from_wire(0), Some(ChecksumType::Sha1));
        assert_eq!(ChecksumType::from_wire(1), Some(ChecksumType::Sha256));
        assert_eq!(ChecksumType::from_wire(2), None);
        assert_eq!(ChecksumType::from_wire(-1), None);
        assert_eq!(ChecksumType::Sha1.wire_value(), 0);
        assert_eq!(ChecksumType::Sha256.wire_value(), 1);
    }

    #[test]
    fn checksum_type_digest_lengths_are_twenty_and_thirty_two() {
        assert_eq!(ChecksumType::Sha1.digest_len(), 20);
        assert_eq!(ChecksumType::Sha256.digest_len(), 32);
    }

    #[test]
    fn block_digests_match_the_nist_abc_vectors() {
        assert_eq!(
            ChecksumType::Sha1.digest(b"abc"),
            [
                0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
            ]
        );
        assert_eq!(
            ChecksumType::Sha256.digest(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn stream_digest_kind_follows_the_expected_hash_length() {
        assert_eq!(
            StreamDigestKind::for_expected_hash_len(48),
            StreamDigestKind::Sha384
        );
        assert_eq!(
            StreamDigestKind::for_expected_hash_len(20),
            StreamDigestKind::Sha1
        );
        assert_eq!(
            StreamDigestKind::for_expected_hash_len(0),
            StreamDigestKind::Sha1
        );
        assert_eq!(
            StreamDigestKind::for_expected_hash_len(32),
            StreamDigestKind::Sha1
        );
    }

    #[test]
    fn stream_digest_sha384_matches_the_nist_abc_vector() {
        assert_eq!(
            StreamDigestKind::Sha384.digest(b"abc"),
            vec![
                0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6,
                0x50, 0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a,
                0x43, 0xff, 0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba,
                0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
            ]
        );
        assert_eq!(
            StreamDigestKind::Sha384.digest(b"abc").len(),
            SHA384_DIGEST_LEN
        );
    }

    #[test]
    fn incremental_stream_hashing_matches_a_single_shot_digest() {
        let body: Vec<u8> = (0..4096u32).map(|index| (index % 251) as u8).collect();
        for kind in [StreamDigestKind::Sha1, StreamDigestKind::Sha384] {
            let mut incremental = kind.hasher();
            for slice in body.chunks(97) {
                incremental.update(slice);
            }
            assert_eq!(incremental.finish(), kind.digest(&body));
        }
        for kind in [ChecksumType::Sha1, ChecksumType::Sha256] {
            let mut incremental = kind.hasher();
            for slice in body.chunks(97) {
                incremental.update(slice);
            }
            assert_eq!(incremental.finish(), kind.digest(&body));
        }
    }
}
