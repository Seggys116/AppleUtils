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
}

pub(crate) struct FileData {
    pub bytes: Vec<u8>,
    pub ranges: Vec<(u64, usize)>,
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
        let offset = table
            .checked_mul(self.block)
            .and_then(|n| {
                n.checked_add(((number - 1) % self.inodes_per_group) as u64 * self.inode_size)
            })
            .ok_or("ext4 inode offset overflow")?;
        self.read(offset, self.inode_size as usize)
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
        if size > 16 * 1024 * 1024 {
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
        let mut bytes = Vec::with_capacity(size as usize);
        let mut ranges = Vec::new();
        for (logical, physical, blocks) in extents {
            if bytes.len() as u64 >= size {
                break;
            }
            if logical * self.block != bytes.len() as u64 {
                return Err("sparse or overlapping ext4 boot metadata file".into());
            }
            let len = (blocks * self.block).min(size - bytes.len() as u64) as usize;
            let offset = physical
                .checked_mul(self.block)
                .ok_or("ext4 data offset overflow")?;
            bytes.extend(self.read(offset, len)?);
            ranges.push((offset, len));
        }
        if bytes.len() as u64 != size {
            return Err("incomplete ext4 file extents".into());
        }
        Ok(FileData { bytes, ranges })
    }

    pub fn file(&mut self, path: &str) -> Result<Option<FileData>, String> {
        let mut number = 2;
        for component in path.split('/').filter(|s| !s.is_empty()) {
            if component == "." || component == ".." {
                return Err("invalid ext4 lookup path".into());
            }
            let inode = self.inode(number)?;
            if u16_at(&inode, 0)? & 0xf000 != 0x4000 {
                return Err("ext4 path component is not a directory".into());
            }
            let dir = self.contents(&inode)?.bytes;
            let mut at = 0;
            let mut found = None;
            while at < dir.len() {
                let item = &dir[at..];
                let len = u16_at(item, 4)? as usize;
                let name_len = *item.get(6).ok_or("truncated ext4 directory entry")? as usize;
                if len < 8
                    || !len.is_multiple_of(4)
                    || len > item.len()
                    || name_len > len - 8
                    || at as u64 % self.block + len as u64 > self.block
                {
                    return Err("invalid ext4 directory entry".into());
                }
                let ino = u32_at(item, 0)?;
                if ino != 0 && &item[8..8 + name_len] == component.as_bytes() {
                    found = Some(ino);
                    break;
                }
                at += len;
            }
            let Some(next) = found else {
                return Ok(None);
            };
            number = next;
        }
        let inode = self.inode(number)?;
        if u16_at(&inode, 0)? & 0xf000 != 0x8000 {
            return Err("ext4 boot metadata path is not a regular file".into());
        }
        self.contents(&inode).map(Some)
    }
}
