use std::collections::BTreeMap;
use std::ops::Range;

use crate::crypto::sha256;

use super::{be32, bytes, refusal, usize64};

pub(super) struct ValidatedSignature {
    directory: Range<usize>,
    hashes: usize,
    code_limit: usize,
    code_slots: usize,
}

impl ValidatedSignature {
    pub(super) fn parse(executable: &[u8], signature: Range<usize>) -> Result<Self, String> {
        let blob = bytes(executable, signature.start, signature.len())?;
        if be32(blob, 0)? != 0xfade0cc0 {
            return Err(refusal(
                "signature-superblob",
                "embedded SuperBlob magic required",
            ));
        }
        let length = be32(blob, 4)? as usize;
        let blob = bytes(blob, 0, length)?;
        let count = be32(blob, 8)? as usize;
        let index_end = count
            .checked_mul(8)
            .and_then(|n| n.checked_add(12))
            .ok_or_else(|| refusal("signature-layout", "index overflow"))?;
        bytes(blob, 0, index_end)?;
        let mut slots = BTreeMap::new();
        let mut ranges: Vec<Range<usize>> = Vec::new();
        for index in 0..count {
            let slot = be32(blob, 12 + index * 8)?;
            let offset = be32(blob, 16 + index * 8)? as usize;
            let size = be32(blob, offset + 4)? as usize;
            if size < 8 || offset < index_end {
                return Err(refusal(
                    "signature-layout",
                    "subblob overlaps index or has short header",
                ));
            }
            let subblob = bytes(blob, offset, size)?;
            let range = offset..offset + size;
            if ranges
                .iter()
                .any(|other| range.start < other.end && other.start < range.end)
                || slots.insert(slot, range.clone()).is_some()
            {
                return Err(refusal(
                    "signature-layout",
                    "overlapping blobs or duplicate slots",
                ));
            }
            ranges.push(range);
            if be32(subblob, 0)? == 0xfade0c02 && slot != 0 {
                return Err(refusal(
                    "signature-directory",
                    "alternate CodeDirectory requires its own proven recipe",
                ));
            }
        }
        let cd_range = slots
            .get(&0)
            .ok_or_else(|| refusal("signature-directory", "primary CodeDirectory not found"))?
            .clone();
        let cd = &blob[cd_range.clone()];
        if be32(cd, 0)? != 0xfade0c02 {
            return Err(refusal(
                "signature-directory",
                "invalid primary CodeDirectory magic",
            ));
        }
        let version = be32(cd, 8)?;
        let header_size = match version {
            0x20000 => 44,
            0x20100 => 48,
            0x20200 => 52,
            0x20300 => 64,
            0x20400 => 88,
            0x20500 => 96,
            0x20600 => 108,
            _ => {
                return Err(refusal(
                    "signature-version",
                    format!("CodeDirectory {version:#x} is not proven"),
                ));
            }
        };
        bytes(cd, 0, header_size)?;
        if be32(cd, 12)? & 2 == 0 || cd[36] != 32 || cd[37] != 2 || cd[39] != 12 {
            return Err(refusal(
                "signature-format",
                "ad-hoc SHA256 with 4096-byte pages required",
            ));
        }
        if version >= 0x20100 && be32(cd, 44)? != 0 {
            return Err(refusal(
                "signature-scatter",
                "scatter coverage is not proven",
            ));
        }
        if version >= 0x20500 && be32(cd, 92)? != 0 {
            return Err(refusal(
                "signature-preencrypt",
                "pre-encryption hash coverage is not proven",
            ));
        }
        let ident = be32(cd, 20)? as usize;
        let hash_offset = be32(cd, 16)? as usize;
        let special = be32(cd, 24)? as usize;
        let code_slots = be32(cd, 28)? as usize;
        let mut code_limit = be32(cd, 32)? as usize;
        if version >= 0x20300 {
            let limit64 = u64::from_be_bytes(bytes(cd, 56, 8)?.try_into().unwrap());
            if limit64 != 0 {
                code_limit = usize64(limit64)?;
            }
        }
        if code_limit == 0
            || code_limit != signature.start
            || code_slots != code_limit.div_ceil(4096)
        {
            return Err(refusal(
                "signature-coverage",
                "code slots must cover all bytes before LC_CODE_SIGNATURE",
            ));
        }
        let special_bytes = special
            .checked_mul(32)
            .ok_or_else(|| refusal("signature-layout", "special slot count overflow"))?;
        let hashes_start = hash_offset
            .checked_sub(special_bytes)
            .ok_or_else(|| refusal("signature-layout", "special hashes precede directory"))?;
        let hashes_end = code_slots
            .checked_mul(32)
            .and_then(|n| n.checked_add(hash_offset))
            .ok_or_else(|| refusal("signature-layout", "code slot count overflow"))?;
        bytes(
            cd,
            hashes_start,
            hashes_end
                .checked_sub(hashes_start)
                .ok_or_else(|| refusal("signature-layout", "hash array overflow"))?,
        )?;
        if hashes_start < header_size
            || ident < header_size
            || ident >= hashes_start
            || !cd[ident..hashes_start].contains(&0)
        {
            return Err(refusal(
                "signature-identifier",
                "identifier overlaps hashes or is unterminated",
            ));
        }
        if version >= 0x20200 {
            let team = be32(cd, 48)? as usize;
            if team != 0
                && (team < header_size
                    || team >= hashes_start
                    || !cd[team..hashes_start].contains(&0))
            {
                return Err(refusal("signature-team", "team identifier is invalid"));
            }
        }
        let cms = slots
            .get(&0x10000)
            .ok_or_else(|| refusal("signature-cms", "null CMS wrapper not found"))?;
        if cms.len() != 8 || be32(blob, cms.start)? != 0xfade0b01 {
            return Err(refusal(
                "signature-cms",
                "non-null CMS cannot be preserved after ad-hoc editing",
            ));
        }
        for slot in 1..=special {
            let expected = &cd[hash_offset - slot * 32..hash_offset - (slot - 1) * 32];
            match slots.get(&(slot as u32)) {
                Some(range) => {
                    let magic = be32(blob, range.start)?;
                    let expected_magic = match slot {
                        2 => 0xfade0c01,
                        5 => 0xfade7171,
                        7 => 0xfade7172,
                        8..=11 => 0xfade8181,
                        _ => {
                            return Err(refusal(
                                "signature-special-slot",
                                format!("slot {slot} format is not proven"),
                            ));
                        }
                    };
                    if magic != expected_magic || expected != sha256(&blob[range.clone()]) {
                        return Err(refusal(
                            "signature-special-hash",
                            format!("slot {slot} fails validation"),
                        ));
                    }
                }
                None if expected.iter().all(|byte| *byte == 0) => {}
                None => {
                    return Err(refusal(
                        "signature-special-content",
                        format!("slot {slot} content is required to validate its hash"),
                    ));
                }
            }
        }
        for slot in slots
            .keys()
            .copied()
            .filter(|slot| *slot > 0 && *slot < 0x1000)
        {
            if slot as usize > special {
                return Err(refusal(
                    "signature-special-coverage",
                    format!("blob slot {slot} is outside special hash coverage"),
                ));
            }
        }
        for index in 0..code_slots {
            let start = index * 4096;
            let end = (start + 4096).min(code_limit);
            if cd[hash_offset + index * 32..hash_offset + (index + 1) * 32]
                != sha256(&executable[start..end])
            {
                return Err(refusal(
                    "signature-code-hash",
                    format!("page {index} fails validation"),
                ));
            }
        }
        let directory = signature.start + cd_range.start..signature.start + cd_range.end;
        Ok(Self {
            hashes: directory.start + hash_offset,
            directory,
            code_limit,
            code_slots,
        })
    }

    pub(super) fn rehash(
        &self,
        original: &[u8],
        patched: &mut [u8],
    ) -> Result<([u8; 20], [u8; 20]), String> {
        if original.len() != patched.len()
            || original[self.code_limit..] != patched[self.code_limit..]
        {
            return Err(refusal(
                "signature-edit",
                "recipe changed file size or original signature bytes",
            ));
        }
        let old = sha256(&original[self.directory.clone()]);
        for index in 0..self.code_slots {
            let start = index * 4096;
            let end = (start + 4096).min(self.code_limit);
            if original[start..end] != patched[start..end] {
                let digest = sha256(&patched[start..end]);
                let offset = self.hashes + index * 32;
                patched[offset..offset + 32].copy_from_slice(&digest);
            }
        }
        let new = sha256(&patched[self.directory.clone()]);
        Ok((old[..20].try_into().unwrap(), new[..20].try_into().unwrap()))
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    pub(crate) fn fixture(mut code: Vec<u8>) -> (Vec<u8>, Range<usize>) {
        let code_limit = code.len();
        let special_blobs = [
            (2u32, 0xfade0c01u32),
            (5, 0xfade7171),
            (7, 0xfade7172),
            (8, 0xfade8181),
        ];
        let hash_offset = 96 + 8 * 32;
        let mut cd = vec![0u8; hash_offset + code_limit.div_ceil(4096) * 32];
        let length = cd.len() as u32;
        for (offset, value) in [
            (0, 0xfade0c02),
            (4, length),
            (8, 0x20400),
            (12, 2),
            (16, hash_offset as u32),
            (20, 88),
            (24, 8),
            (28, code_limit.div_ceil(4096) as u32),
            (32, code_limit as u32),
        ] {
            cd[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        cd[36..40].copy_from_slice(&[32, 2, 0, 12]);
        cd[88..96].copy_from_slice(b"fixture\0");
        for (index, page) in code.chunks(4096).enumerate() {
            cd[hash_offset + index * 32..hash_offset + (index + 1) * 32]
                .copy_from_slice(&sha256(page));
        }
        let mut blobs = Vec::new();
        for (slot, magic) in special_blobs {
            let mut blob = magic.to_be_bytes().to_vec();
            blob.extend_from_slice(&12u32.to_be_bytes());
            blob.extend_from_slice(&slot.to_be_bytes());
            let offset = hash_offset - slot as usize * 32;
            cd[offset..offset + 32].copy_from_slice(&sha256(&blob));
            blobs.push((slot, blob));
        }
        blobs.insert(0, (0, cd));
        let mut cms = 0xfade0b01u32.to_be_bytes().to_vec();
        cms.extend_from_slice(&8u32.to_be_bytes());
        blobs.push((0x10000, cms));
        let mut superblob = vec![0u8; 12 + blobs.len() * 8];
        superblob[..4].copy_from_slice(&0xfade0cc0u32.to_be_bytes());
        superblob[8..12].copy_from_slice(&(blobs.len() as u32).to_be_bytes());
        for (index, (slot, blob)) in blobs.into_iter().enumerate() {
            let offset = superblob.len() as u32;
            superblob[12 + index * 8..16 + index * 8].copy_from_slice(&slot.to_be_bytes());
            superblob[16 + index * 8..20 + index * 8].copy_from_slice(&offset.to_be_bytes());
            superblob.extend(blob);
        }
        let size = superblob.len() as u32;
        superblob[4..8].copy_from_slice(&size.to_be_bytes());
        code.extend(superblob);
        let end = code.len();
        (code, code_limit..end)
    }

    #[test]
    fn rehash_preserves_blobs_metadata_and_unaffected_pages() {
        let (input, range) = fixture(vec![0x35; 8193]);
        let signature = ValidatedSignature::parse(&input, range.clone()).unwrap();
        let mut output = input.clone();
        output[4133] = 0x57;
        let (old, new) = signature.rehash(&input, &mut output).unwrap();
        assert_eq!(old, sha256(&input[signature.directory.clone()])[..20]);
        assert_eq!(new, sha256(&output[signature.directory.clone()])[..20]);
        let changed_hash = signature.hashes + 32..signature.hashes + 64;
        assert_eq!(
            &output[range.start..changed_hash.start],
            &input[range.start..changed_hash.start]
        );
        assert_eq!(&output[changed_hash.end..], &input[changed_hash.end..]);
        assert_eq!(&output[changed_hash.clone()], &sha256(&output[4096..8192]));
        ValidatedSignature::parse(&output, range).unwrap();
    }

    #[test]
    fn corrupted_code_and_special_hashes_record_named_refusals() {
        let (input, range) = fixture(vec![0x35; 8193]);
        let mut code = input.clone();
        code[1] ^= 1;
        assert!(
            ValidatedSignature::parse(&code, range.clone())
                .err()
                .unwrap()
                .starts_with("skip-tcon-signature-code-hash:")
        );
        let signature = ValidatedSignature::parse(&input, range.clone()).unwrap();
        let mut special = input;
        special[signature.hashes - 8 * 32] ^= 1;
        assert!(
            ValidatedSignature::parse(&special, range)
                .err()
                .unwrap()
                .starts_with("skip-tcon-signature-special-hash:")
        );
    }
}
