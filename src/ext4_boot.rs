use std::io::{Read, Seek, SeekFrom};

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2)
            .ok_or("truncated ext4 field")?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or("truncated ext4 field")?
            .try_into()
            .unwrap(),
    ))
}

/// ext4 inode crc32c over seed, inode number, generation and the inode with its checksum
/// fields zeroed; the high half exists only when i_extra_isize reaches i_checksum_hi.
pub(crate) fn inode_checksum(seed: u32, number: u32, raw: &[u8]) -> Result<(u32, bool), String> {
    use crate::crypto::crc32::crc32c_update as crc;
    if raw.len() < 128 || (raw.len() > 128 && raw.len() < 0x84) {
        return Err("invalid ext4 inode size for checksum".into());
    }
    let mut checksum = crc(crc(seed, &number.to_le_bytes()), &raw[100..104]);
    checksum = crc(checksum, &raw[..0x7c]);
    checksum = crc(checksum, &[0, 0]);
    checksum = crc(checksum, &raw[0x7e..128]);
    let mut has_high = false;
    if raw.len() > 128 {
        checksum = crc(checksum, &raw[128..0x82]);
        let mut offset = 0x82;
        if 128 + u16_at(raw, 0x80)? as usize >= 0x84 {
            checksum = crc(checksum, &[0, 0]);
            offset = 0x84;
            has_high = true;
        }
        checksum = crc(checksum, &raw[offset..]);
    }
    Ok((checksum, has_high))
}

pub(crate) struct Ext4<R> {
    source: R,
    length: u64,
    block: u64,
    inodes_per_group: u32,
    inode_size: u64,
    descriptor_size: u64,
    descriptor_start: u64,
    inode_count: u32,
    protected: Vec<(u64, u64)>,
    inode_checksum_seed: Option<u32>,
}

pub(crate) struct FileData {
    pub bytes: Vec<u8>,
    pub ranges: Vec<(u64, usize)>,
}

pub(crate) struct FileResize {
    pub ranges: Vec<(u64, usize)>,
    pub inode_offset: u64,
    pub inode: Vec<u8>,
}

impl<R: Read + Seek> Ext4<R> {
    pub fn open(mut source: R) -> Result<Option<Self>, String> {
        let length = source.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
        if length < 2048 {
            return Ok(None);
        }
        source
            .seek(SeekFrom::Start(1024))
            .map_err(|e| e.to_string())?;
        let mut sb = [0; 1024];
        source.read_exact(&mut sb).map_err(|e| e.to_string())?;
        if u16_at(&sb, 56)? != 0xef53 {
            return Ok(None);
        }
        let log = u32_at(&sb, 24)?;
        if log > 6 {
            return Err("invalid ext4 block size".into());
        }
        let block = 1024u64 << log;
        let incompat = u32_at(&sb, 96)?;
        if incompat & (0x4 | 0x10 | 0x10000 | 0x20000 | 0x8000) != 0 {
            return Err(
                "ext4 boot image requires clean journal and supported metadata layout".into(),
            );
        }
        let inode_size = if u32_at(&sb, 76)? == 0 {
            128
        } else {
            u16_at(&sb, 88)? as u64
        };
        let descriptor_size = if incompat & 0x80 != 0 {
            u16_at(&sb, 254)? as u64
        } else {
            32
        };
        let inodes_per_group = u32_at(&sb, 40)?;
        if inode_size < 128
            || inode_size > block
            || descriptor_size < 32
            || descriptor_size > block
            || inodes_per_group == 0
        {
            return Err("invalid ext4 inode geometry".into());
        }
        let inode_checksum_seed = if u32_at(&sb, 100)? & 0x400 != 0 {
            if sb[0x175] != 1 {
                return Err("ext4 metadata checksum type is not crc32c".into());
            }
            Some(if incompat & 0x2000 != 0 {
                u32_at(&sb, 0x270)?
            } else {
                crate::crypto::crc32::crc32c_update(u32::MAX, &sb[0x68..0x78])
            })
        } else {
            None
        };
        let mut fs = Self {
            source,
            length,
            block,
            inodes_per_group,
            inode_size,
            descriptor_size,
            descriptor_start: (u32_at(&sb, 20)? as u64 + 1) * block,
            inode_count: u32_at(&sb, 0)?,
            protected: vec![(0, 2048)],
            inode_checksum_seed,
        };
        fs.protect_metadata(&sb)?;
        Ok(Some(fs))
    }

    fn protect_metadata(&mut self, sb: &[u8]) -> Result<(), String> {
        let blocks = u32_at(sb, 4)? as u64
            | if u32_at(sb, 96)? & 0x80 != 0 {
                (u32_at(sb, 336)? as u64) << 32
            } else {
                0
            };
        let per_group = u32_at(sb, 32)? as u64;
        let first = u32_at(sb, 20)? as u64;
        if per_group == 0
            || blocks <= first
            || blocks
                .checked_mul(self.block)
                .is_none_or(|n| n > self.length)
        {
            return Err("invalid ext4 block group geometry".into());
        }
        let groups = (blocks - first).div_ceil(per_group);
        if groups > 65536 {
            return Err("ext4 boot image group limit exceeded".into());
        }
        let desc_blocks = (groups * self.descriptor_size).div_ceil(self.block);
        let inode_blocks = (self.inodes_per_group as u64 * self.inode_size).div_ceil(self.block);
        let sparse = u32_at(sb, 100)? & 1 != 0;
        let sparse2 = u32_at(sb, 92)? & 0x200 != 0;
        let power = |mut n: u64, base: u64| {
            if n == 0 {
                return false;
            }
            while n.is_multiple_of(base) {
                n /= base;
            }
            n == 1
        };
        for group in 0..groups {
            let has_super = if sparse2 {
                group == 0 || group == u32_at(sb, 588)? as u64 || group == u32_at(sb, 592)? as u64
            } else {
                !sparse
                    || group == 0
                    || group == 1
                    || power(group, 3)
                    || power(group, 5)
                    || power(group, 7)
            };
            if has_super {
                let start = (first + group * per_group) * self.block;
                self.protected.push((
                    start,
                    start + (1 + desc_blocks + u16_at(sb, 206)? as u64) * self.block,
                ));
            }
            let desc = self.read(
                self.descriptor_start + group * self.descriptor_size,
                self.descriptor_size as usize,
            )?;
            for (lo, hi, size) in [(0, 32, 1), (4, 36, 1), (8, 40, inode_blocks)] {
                let block = u32_at(&desc, lo)? as u64
                    | if self.descriptor_size >= 64 {
                        (u32_at(&desc, hi)? as u64) << 32
                    } else {
                        0
                    };
                let start = block
                    .checked_mul(self.block)
                    .ok_or("ext4 metadata offset overflow")?;
                let end = start
                    .checked_add(size * self.block)
                    .ok_or("ext4 metadata extent overflow")?;
                if end > self.length {
                    return Err("ext4 metadata outside image".into());
                }
                self.protected.push((start, end));
            }
        }
        Ok(())
    }

    fn read(&mut self, offset: u64, size: usize) -> Result<Vec<u8>, String> {
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err("ext4 read outside image".into());
        }
        let mut bytes = vec![0; size];
        self.source
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        self.source
            .read_exact(&mut bytes)
            .map_err(|e| e.to_string())?;
        Ok(bytes)
    }

    fn inode(&mut self, number: u32) -> Result<Vec<u8>, String> {
        let offset = self.inode_offset(number)?;
        self.read(offset, self.inode_size as usize)
    }

    fn inode_offset(&mut self, number: u32) -> Result<u64, String> {
        if number == 0 || number > self.inode_count {
            return Err("invalid ext4 inode number".into());
        }
        let group = (number - 1) / self.inodes_per_group;
        let desc = self.read(
            self.descriptor_start + group as u64 * self.descriptor_size,
            self.descriptor_size as usize,
        )?;
        let table = u32_at(&desc, 8)? as u64
            | if self.descriptor_size >= 64 {
                (u32_at(&desc, 40)? as u64) << 32
            } else {
                0
            };
        table
            .checked_mul(self.block)
            .and_then(|n| {
                n.checked_add(((number - 1) % self.inodes_per_group) as u64 * self.inode_size)
            })
            .ok_or_else(|| "ext4 inode offset overflow".to_string())
    }

    fn extents(
        &mut self,
        node: &[u8],
        expected_depth: Option<u16>,
        out: &mut Vec<(u64, u64, u64)>,
    ) -> Result<(), String> {
        if u16_at(node, 0)? != 0xf30a {
            return Err("invalid ext4 extent header".into());
        }
        let count = u16_at(node, 2)? as usize;
        let depth = u16_at(node, 6)?;
        if depth > 5
            || expected_depth.is_some_and(|n| n != depth)
            || count > u16_at(node, 4)? as usize
            || 12 + count * 12 > node.len()
        {
            return Err("invalid ext4 extent tree geometry".into());
        }
        if out.len() + count > 4096 {
            return Err("ext4 boot metadata extent limit exceeded".into());
        }
        for entry in node[12..12 + count * 12].as_chunks::<12>().0 {
            let logical = u32_at(entry, 0)? as u64;
            if depth == 0 {
                let size = u16_at(entry, 4)?;
                if size == 0 || size > 32768 {
                    return Err("uninitialized ext4 boot metadata extent".into());
                }
                let physical = u32_at(entry, 8)? as u64 | (u16_at(entry, 6)? as u64) << 32;
                if physical == 0 {
                    return Err("invalid ext4 data block".into());
                }
                out.push((logical, physical, size as u64));
            } else {
                let physical = u32_at(entry, 4)? as u64 | (u16_at(entry, 8)? as u64) << 32;
                self.protected.push((
                    physical
                        .checked_mul(self.block)
                        .ok_or("ext4 extent offset overflow")?,
                    physical
                        .checked_add(1)
                        .and_then(|n| n.checked_mul(self.block))
                        .ok_or("ext4 extent offset overflow")?,
                ));
                let child = self.read(
                    physical
                        .checked_mul(self.block)
                        .ok_or("ext4 extent offset overflow")?,
                    self.block as usize,
                )?;
                self.extents(&child, Some(depth - 1), out)?;
            }
        }
        Ok(())
    }

    fn contents(&mut self, inode: &[u8]) -> Result<FileData, String> {
        let size = u32_at(inode, 4)? as u64 | (u32_at(inode, 108)? as u64) << 32;
        let ranges = self.mapped(inode, size)?;
        let mut bytes = Vec::with_capacity(size as usize);
        for &(offset, len) in &ranges {
            bytes.extend(self.read(offset, len)?);
        }
        Ok(FileData { bytes, ranges })
    }

    /// Physical byte ranges holding the first `length` bytes of the file, taken only from
    /// blocks its extents already map.
    fn mapped(&mut self, inode: &[u8], length: u64) -> Result<Vec<(u64, usize)>, String> {
        if length > 16 * 1024 * 1024 {
            return Err("ext4 boot metadata file exceeds size limit".into());
        }
        if u32_at(inode, 32)? & 0x80000 == 0 {
            return Err("ext4 boot metadata requires extent mapping".into());
        }
        let mut extents = Vec::new();
        self.extents(&inode[40..100], None, &mut extents)?;
        let mut physical_ranges = Vec::new();
        let mut previous_end = 0;
        for &(logical, physical, blocks) in &extents {
            let end = logical
                .checked_add(blocks)
                .ok_or("ext4 logical extent overflow")?;
            let start = physical
                .checked_mul(self.block)
                .ok_or("ext4 physical extent overflow")?;
            let stop = physical
                .checked_add(blocks)
                .and_then(|n| n.checked_mul(self.block))
                .ok_or("ext4 physical extent overflow")?;
            if logical < previous_end
                || stop > self.length
                || physical_ranges.iter().any(|&(a, b)| start < b && a < stop)
                || self.protected.iter().any(|&(a, b)| start < b && a < stop)
            {
                return Err("ext4 data extent overlaps metadata or another extent".into());
            }
            physical_ranges.push((start, stop));
            previous_end = end;
        }
        let mut covered = 0u64;
        let mut ranges = Vec::new();
        for (logical, physical, blocks) in extents {
            if covered >= length {
                break;
            }
            if logical * self.block != covered {
                return Err("sparse or overlapping ext4 boot metadata file".into());
            }
            let len = (blocks * self.block).min(length - covered) as usize;
            let offset = physical
                .checked_mul(self.block)
                .ok_or("ext4 data offset overflow")?;
            ranges.push((offset, len));
            covered += len as u64;
        }
        if covered != length {
            return Err("incomplete ext4 file extents".into());
        }
        Ok(ranges)
    }

    /// Plans a change of a regular file's length inside the blocks it already owns: the data
    /// ranges for the new length and the inode carrying the new size and, on a
    /// metadata_csum filesystem, its recomputed checksum. Allocation is never changed, so a
    /// length past the last mapped block is refused.
    pub fn resize_in_place(
        &mut self,
        path: &str,
        length: u64,
    ) -> Result<Option<FileResize>, String> {
        let Some(number) = self.inode_at(path)? else {
            return Ok(None);
        };
        let inode_offset = self.inode_offset(number)?;
        let mut inode = self.inode(number)?;
        if u16_at(&inode, 0)? & 0xf000 != 0x8000 {
            return Ok(None);
        }
        let ranges = self
            .mapped(&inode, length)
            .map_err(|e| format!("{path} cannot hold {length} bytes in its blocks: {e}"))?;
        if let Some(seed) = self.inode_checksum_seed {
            let (checksum, has_high) = inode_checksum(seed, number, &inode)?;
            let stored_low = u16_at(&inode, 0x7c)?;
            let stored_high = if has_high { u16_at(&inode, 0x82)? } else { 0 };
            if stored_low != checksum as u16 || (has_high && stored_high != (checksum >> 16) as u16)
            {
                return Err(format!("{path} inode checksum does not verify"));
            }
        }
        inode[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        inode[108..112].copy_from_slice(&((length >> 32) as u32).to_le_bytes());
        if let Some(seed) = self.inode_checksum_seed {
            let (checksum, has_high) = inode_checksum(seed, number, &inode)?;
            inode[0x7c..0x7e].copy_from_slice(&(checksum as u16).to_le_bytes());
            if has_high {
                inode[0x82..0x84].copy_from_slice(&((checksum >> 16) as u16).to_le_bytes());
            }
        }
        Ok(Some(FileResize {
            ranges,
            inode_offset,
            inode,
        }))
    }

    fn directory_bytes(&mut self, number: u32) -> Result<Option<Vec<u8>>, String> {
        let inode = self.inode(number)?;
        if u16_at(&inode, 0)? & 0xf000 != 0x4000 {
            return Ok(None);
        }
        Ok(Some(self.contents(&inode)?.bytes))
    }

    fn walk_dirent(dir: &[u8], at: usize, block: u64) -> Result<(u32, usize, &[u8], u8), String> {
        let item = &dir[at..];
        let len = u16_at(item, 4)? as usize;
        let name_len = *item.get(6).ok_or("truncated ext4 directory entry")? as usize;
        let file_type = *item.get(7).ok_or("truncated ext4 directory entry")?;
        if len < 8
            || !len.is_multiple_of(4)
            || len > item.len()
            || name_len > len - 8
            || at as u64 % block + len as u64 > block
        {
            return Err("invalid ext4 directory entry".into());
        }
        Ok((u32_at(item, 0)?, len, &item[8..8 + name_len], file_type))
    }

    fn lookup(&mut self, parent: u32, name: &str) -> Result<Option<u32>, String> {
        let Some(dir) = self.directory_bytes(parent)? else {
            return Ok(None);
        };
        let mut at = 0;
        while at < dir.len() {
            let (ino, len, bytes, _) = Self::walk_dirent(&dir, at, self.block)?;
            if ino != 0 && bytes == name.as_bytes() {
                return Ok(Some(ino));
            }
            at += len;
        }
        Ok(None)
    }

    fn inode_at(&mut self, path: &str) -> Result<Option<u32>, String> {
        let mut number = 2;
        for component in path.split('/').filter(|s| !s.is_empty()) {
            if component == "." || component == ".." {
                return Err("invalid ext4 lookup path".into());
            }
            let Some(next) = self.lookup(number, component)? else {
                return Ok(None);
            };
            number = next;
        }
        Ok(Some(number))
    }

    pub fn file(&mut self, path: &str) -> Result<Option<FileData>, String> {
        let Some(number) = self.inode_at(path)? else {
            return Ok(None);
        };
        let inode = self.inode(number)?;
        if u16_at(&inode, 0)? & 0xf000 != 0x8000 {
            return Ok(None);
        }
        self.contents(&inode).map(Some)
    }

    pub fn files_in(&mut self, path: &str) -> Result<Option<Vec<String>>, String> {
        let Some(number) = self.inode_at(path)? else {
            return Ok(None);
        };
        let Some(dir) = self.directory_bytes(number)? else {
            return Ok(None);
        };
        let mut names = Vec::new();
        let mut at = 0;
        while at < dir.len() {
            let (ino, len, bytes, file_type) = Self::walk_dirent(&dir, at, self.block)?;
            if ino != 0 && file_type != 2 {
                let name =
                    std::str::from_utf8(bytes).map_err(|_| "ext4 directory name is not UTF-8")?;
                if name != "." && name != ".." {
                    if names.len() >= 256 {
                        return Err("ext4 directory listing limit exceeded".into());
                    }
                    names.push(name.to_string());
                }
            }
            at += len;
        }
        Ok(Some(names))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Inode 1616 of the Fedora Asahi Remix 44 Workstation boot.img, its BLS entry, with the
    // filesystem's s_checksum_seed. mkfs.ext4 and the kernel wrote the stored checksum.
    const FEDORA_BLS_INODE: &str = "a48100009f0100006aee9a6a6aee9a6a6aee9a6a00000000000001000800000000000800080000000af3010004000000000000000000000001000000411001000000000000000000000000000000000000000000000000000000000000000000000000009db84d2000000000000000000000000000000000000000002d34000020008fae3026e32a3026e32a0c96c12a6aee9a6a0467f6060000000000000000000002ea07064000000000001c0000000000000073656c696e7578000000000000000000000000000000000000000000000000000000000000000000000000000000000073797374656d5f753a6f626a6563745f723a626f6f745f743a733000";
    const FEDORA_CHECKSUM_SEED: u32 = 0xd088_1913;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn inode_checksum_matches_mkfs_written_inode() {
        let inode = hex(FEDORA_BLS_INODE);
        assert_eq!(inode.len(), 256);
        let (checksum, has_high) = inode_checksum(FEDORA_CHECKSUM_SEED, 1616, &inode).unwrap();
        assert!(has_high);
        assert_eq!(checksum, 0xae8f_342d);
        assert_eq!(u16_at(&inode, 0x7c).unwrap(), 0x342d);
        assert_eq!(u16_at(&inode, 0x82).unwrap(), 0xae8f);
    }
}
