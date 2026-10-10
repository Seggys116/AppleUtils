use std::ops::Range;

use super::{bytes, le32, le64, refusal, usize64};

struct Section {
    name: String,
    address: u64,
    size: u64,
    offset: usize,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
}

struct Segment {
    address: u64,
    offset: usize,
    size: usize,
}

pub(super) struct MachO {
    pub(super) signature: Range<usize>,
    sections: Vec<Section>,
    segments: Vec<Segment>,
    symbols: (usize, usize, usize, usize),
    indirect: (usize, usize),
    fixups: Range<usize>,
    base: u64,
}

fn name(data: &[u8]) -> Result<String, String> {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    std::str::from_utf8(&data[..end])
        .map(str::to_owned)
        .map_err(|_| refusal("macho-name", "non-UTF8 name"))
}

impl MachO {
    pub(super) fn parse(data: &[u8]) -> Result<Self, String> {
        if le32(data, 0)? != 0xfeedfacf
            || le32(data, 4)? != 0x0100000c
            || le32(data, 8)? & 0x00ffffff != 2
            || le32(data, 12)? != 2
        {
            return Err(refusal("macho-arm64e", "thin arm64e MH_EXECUTE required"));
        }
        let commands = le32(data, 16)? as usize;
        let command_size = le32(data, 20)? as usize;
        bytes(data, 32, command_size)?;
        let command_end = 32 + command_size;
        let mut offset = 32;
        let mut sections = Vec::new();
        let mut segments = Vec::new();
        let mut signature = None;
        let mut symbols = None;
        let mut indirect = None;
        let mut fixups = None;
        for _ in 0..commands {
            let command = le32(data, offset)?;
            let size = le32(data, offset + 4)? as usize;
            if size < 8
                || !size.is_multiple_of(8)
                || offset.checked_add(size).is_none_or(|end| end > command_end)
            {
                return Err(refusal("macho-commands", "invalid load-command length"));
            }
            let lc = bytes(data, offset, size)?;
            match command {
                0x19 => {
                    bytes(lc, 0, 72)?;
                    let address = le64(lc, 24)?;
                    let file_offset = usize64(le64(lc, 40)?)?;
                    let file_size = usize64(le64(lc, 48)?)?;
                    bytes(data, file_offset, file_size)?;
                    if address.checked_add(file_size as u64).is_none() {
                        return Err(refusal("macho-segment", "VM address overflow"));
                    }
                    let count = le32(lc, 64)? as usize;
                    if count.checked_mul(80).and_then(|n| n.checked_add(72)) != Some(size) {
                        return Err(refusal(
                            "macho-sections",
                            "section count disagrees with segment command",
                        ));
                    }
                    for index in 0..count {
                        let section = bytes(lc, 72 + index * 80, 80)?;
                        let entry = Section {
                            name: name(&section[..16])?,
                            address: le64(section, 32)?,
                            size: le64(section, 40)?,
                            offset: le32(section, 48)? as usize,
                            flags: le32(section, 64)?,
                            reserved1: le32(section, 68)?,
                            reserved2: le32(section, 72)?,
                        };
                        if !matches!(entry.flags & 0xff, 1 | 0xc | 0x12) {
                            let section_size = usize64(entry.size)?;
                            bytes(data, entry.offset, section_size)?;
                            if entry.offset < file_offset
                                || entry.offset + section_size > file_offset + file_size
                                || entry.address < address
                                || entry.address - address != (entry.offset - file_offset) as u64
                            {
                                return Err(refusal(
                                    "macho-section-map",
                                    format!("{} disagrees with segment mapping", entry.name),
                                ));
                            }
                        }
                        sections.push(entry);
                    }
                    segments.push(Segment {
                        address,
                        offset: file_offset,
                        size: file_size,
                    });
                }
                0x2 => {
                    if size != 24 || symbols.is_some() {
                        return Err(refusal("macho-symbols", "invalid or duplicate LC_SYMTAB"));
                    }
                    symbols = Some((
                        le32(lc, 8)? as usize,
                        le32(lc, 12)? as usize,
                        le32(lc, 16)? as usize,
                        le32(lc, 20)? as usize,
                    ));
                }
                0xb => {
                    if size != 80 || indirect.is_some() {
                        return Err(refusal(
                            "macho-indirect",
                            "invalid or duplicate LC_DYSYMTAB",
                        ));
                    }
                    indirect = Some((le32(lc, 56)? as usize, le32(lc, 60)? as usize));
                }
                0x1d | 0x80000034 => {
                    if size != 16 {
                        return Err(refusal("macho-linkedit", "invalid linkedit command"));
                    }
                    let start = le32(lc, 8)? as usize;
                    let length = le32(lc, 12)? as usize;
                    bytes(data, start, length)?;
                    let target = if command == 0x1d {
                        &mut signature
                    } else {
                        &mut fixups
                    };
                    if target.replace(start..start + length).is_some() {
                        return Err(refusal("macho-linkedit", "duplicate linkedit command"));
                    }
                }
                _ => {}
            }
            offset += size;
        }
        if offset != command_end {
            return Err(refusal(
                "macho-commands",
                "load-command count disagrees with size",
            ));
        }
        let symbols = symbols.ok_or_else(|| refusal("macho-symbols", "LC_SYMTAB not found"))?;
        bytes(
            data,
            symbols.0,
            symbols
                .1
                .checked_mul(16)
                .ok_or_else(|| refusal("macho-symbols", "count overflow"))?,
        )?;
        bytes(data, symbols.2, symbols.3)?;
        let indirect =
            indirect.ok_or_else(|| refusal("macho-indirect", "LC_DYSYMTAB not found"))?;
        bytes(
            data,
            indirect.0,
            indirect
                .1
                .checked_mul(4)
                .ok_or_else(|| refusal("macho-indirect", "count overflow"))?,
        )?;
        let base = segments
            .iter()
            .filter(|segment| segment.size != 0 && segment.offset == 0)
            .map(|segment| segment.address)
            .min()
            .ok_or_else(|| refusal("macho-base", "header segment not found"))?;
        Ok(Self {
            signature: signature
                .ok_or_else(|| refusal("macho-signature", "LC_CODE_SIGNATURE not found"))?,
            fixups: fixups
                .ok_or_else(|| refusal("macho-fixups", "LC_DYLD_CHAINED_FIXUPS not found"))?,
            sections,
            segments,
            symbols,
            indirect,
            base,
        })
    }

    fn offset(&self, address: u64, length: usize) -> Result<usize, String> {
        let mut found = None;
        for segment in &self.segments {
            if let Some(delta) = address.checked_sub(segment.address)
                && delta <= segment.size as u64
                && length as u64 <= segment.size as u64 - delta
                && found.replace(segment.offset + delta as usize).is_some()
            {
                return Err(refusal("macho-map", "overlapping VM mappings"));
            }
        }
        found.ok_or_else(|| refusal("macho-map", format!("unmapped address {address:#x}")))
    }

    fn symbol(
        &self,
        data: &[u8],
        section: &Section,
        address: u64,
        stride: u32,
    ) -> Result<String, String> {
        if stride == 0
            || address < section.address
            || address - section.address >= section.size
            || !(address - section.address).is_multiple_of(stride as u64)
        {
            return Err(refusal("macho-import", "unaligned import address"));
        }
        let index =
            section.reserved1 as usize + ((address - section.address) / stride as u64) as usize;
        if index >= self.indirect.1 {
            return Err(refusal(
                "macho-import",
                "indirect symbol index out of range",
            ));
        }
        let symbol = le32(data, self.indirect.0 + index * 4)? as usize;
        if symbol >= self.symbols.1 {
            return Err(refusal("macho-import", "symbol index out of range"));
        }
        let entry = bytes(data, self.symbols.0 + symbol * 16, 16)?;
        if entry[4] & 0x0e != 0 || entry[4] & 1 == 0 {
            return Err(refusal(
                "macho-import",
                "external undefined symbol required",
            ));
        }
        let string = le32(entry, 0)? as usize;
        let table = bytes(data, self.symbols.2, self.symbols.3)?;
        let suffix = table
            .get(string..)
            .ok_or_else(|| refusal("macho-import", "string index out of range"))?;
        let end = suffix
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| refusal("macho-import", "unterminated symbol"))?;
        name(&suffix[..end])
    }

    fn imported(
        &self,
        data: &[u8],
        address: u64,
        stub: bool,
        expected: &str,
    ) -> Result<(), String> {
        let section = self
            .sections
            .iter()
            .find(|section| {
                address >= section.address
                    && address - section.address < section.size
                    && section.flags & 0xff == if stub { 8 } else { 6 }
            })
            .ok_or_else(|| {
                refusal(
                    "recipe-import",
                    format!("{expected} import section not found"),
                )
            })?;
        let actual = self.symbol(
            data,
            section,
            address,
            if stub { section.reserved2 } else { 8 },
        )?;
        if actual != expected {
            return Err(refusal(
                "recipe-import",
                format!("expected {expected}, found {actual}"),
            ));
        }
        Ok(())
    }

    fn rebase(&self, data: &[u8], pointer: usize) -> Result<u64, String> {
        let fixups = &data[self.fixups.clone()];
        if le32(fixups, 0)? != 0 {
            return Err(refusal("recipe-fixups", "unsupported fixups version"));
        }
        let starts = le32(fixups, 4)? as usize;
        let count = le32(fixups, starts)? as usize;
        if count != self.segments.len() {
            return Err(refusal("recipe-fixups", "segment count mismatch"));
        }
        for (index, segment) in self.segments.iter().enumerate() {
            if pointer < segment.offset || pointer - segment.offset >= segment.size {
                continue;
            }
            let relative = le32(fixups, starts + 4 + index * 4)? as usize;
            if relative == 0 {
                break;
            }
            let info = starts
                .checked_add(relative)
                .ok_or_else(|| refusal("recipe-fixups", "starts offset overflow"))?;
            let size = le32(fixups, info)? as usize;
            let record = bytes(fixups, info, size)?;
            let u16at = |offset| -> Result<u16, String> {
                Ok(u16::from_le_bytes(
                    bytes(record, offset, 2)?.try_into().unwrap(),
                ))
            };
            let page_size = u16at(4)? as usize;
            let format = u16at(6)?;
            if !matches!(format, 9 | 12)
                || !matches!(page_size, 4096 | 16384)
                || le64(record, 8)? != segment.address - self.base
            {
                return Err(refusal(
                    "recipe-fixups",
                    "arm64e userland chained rebases required",
                ));
            }
            let page = (pointer - segment.offset) / page_size;
            if page >= u16at(20)? as usize {
                break;
            }
            let start = u16at(22 + page * 2)?;
            if start == 0xffff {
                break;
            }
            if start & 0x8000 != 0 {
                return Err(refusal("recipe-fixups", "multi-start pages are not proven"));
            }
            let page_offset = segment.offset + page * page_size;
            let mut chain = start as usize;
            loop {
                if chain + 8 > page_size || page_offset + chain + 8 > segment.offset + segment.size
                {
                    return Err(refusal(
                        "recipe-fixups",
                        "chain exceeds its page or segment",
                    ));
                }
                let value = le64(data, page_offset + chain)?;
                if page_offset + chain == pointer {
                    if value >> 62 != 0 {
                        return Err(refusal(
                            "recipe-cfstring",
                            "string pointer must be an unauthenticated rebase",
                        ));
                    }
                    let target = (value & ((1u64 << 43) - 1)) | (((value >> 43) & 0xff) << 56);
                    return self
                        .base
                        .checked_add(target)
                        .ok_or_else(|| refusal("recipe-cfstring", "rebase target overflow"));
                }
                let next = ((value >> 51) & 0x7ff) as usize;
                if next == 0 {
                    break;
                }
                chain += next * 8;
            }
        }
        Err(refusal(
            "recipe-cfstring",
            "string pointer not found in chained fixups",
        ))
    }

    fn cfstring(&self, data: &[u8], address: u64, expected: &[u8]) -> Result<(), String> {
        let section = self
            .sections
            .iter()
            .find(|section| {
                section.name == "__cfstring"
                    && address >= section.address
                    && address - section.address < section.size
            })
            .ok_or_else(|| refusal("recipe-cfstring", "CFString section not found"))?;
        if !(address - section.address).is_multiple_of(32)
            || section.size - (address - section.address) < 32
        {
            return Err(refusal(
                "recipe-cfstring",
                "unaligned or truncated CFString",
            ));
        }
        let offset = self.offset(address, 32)?;
        if le64(data, offset + 8)? != 0x7c8 || le64(data, offset + 24)? != expected.len() as u64 {
            return Err(refusal(
                "recipe-cfstring",
                "ASCII CFString flags or length mismatch",
            ));
        }
        let target = self.rebase(data, offset + 16)?;
        let string = self.offset(target, expected.len() + 1)?;
        if bytes(data, string, expected.len())? != expected || data[string + expected.len()] != 0 {
            return Err(refusal("recipe-cfstring", "CFString content mismatch"));
        }
        Ok(())
    }
}

fn signed(value: u32, bits: u32) -> i64 {
    ((value << (32 - bits)) as i32 >> (32 - bits)) as i64
}

fn target(pc: u64, delta: i64) -> Result<u64, String> {
    pc.checked_add_signed(delta)
        .ok_or_else(|| refusal("recipe-address", "PC-relative target overflow"))
}

fn branch(word: u32, pc: u64) -> Result<u64, String> {
    target(pc, signed(word & 0x03ffffff, 26) * 4)
}

fn conditional(word: u32, pc: u64) -> Result<u64, String> {
    target(pc, signed((word >> 5) & 0x7ffff, 19) * 4)
}

fn adrp(word: u32, pc: u64) -> Result<u64, String> {
    let immediate = ((word >> 29) & 3) | (((word >> 5) & 0x7ffff) << 2);
    target(pc & !0xfff, signed(immediate, 21) * 4096)
}

fn encode_delta(
    word: u32,
    pc: u64,
    destination: u64,
    bits: u32,
    shift: u32,
) -> Result<u32, String> {
    let delta = destination as i128 - pc as i128;
    let immediate = delta / 4;
    if delta % 4 != 0 || !(-(1i128 << (bits - 1))..(1i128 << (bits - 1))).contains(&immediate) {
        return Err(refusal(
            "recipe-branch-range",
            "relocated branch exceeds immediate range",
        ));
    }
    let mask = ((1u32 << bits) - 1) << shift;
    Ok((word & !mask) | (((immediate as u32) << shift) & mask))
}

fn relocate(word: u32, old_pc: u64, new_pc: u64) -> Result<u32, String> {
    if word & 0xfc000000 == 0x94000000 {
        encode_delta(word, new_pc, branch(word, old_pc)?, 26, 0)
    } else if word & 0xff000010 == 0x54000000 || word & 0x7e000000 == 0x34000000 {
        encode_delta(word, new_pc, conditional(word, old_pc)?, 19, 5)
    } else if word & 0x9f000000 == 0x90000000 {
        let page = adrp(word, old_pc)?;
        let delta = page as i128 - (new_pc & !0xfff) as i128;
        let immediate = delta / 4096;
        if !(-(1i128 << 20)..(1i128 << 20)).contains(&immediate) {
            return Err(refusal(
                "recipe-adrp-range",
                "relocated ADRP exceeds immediate range",
            ));
        }
        let value = immediate as u32 & 0x1fffff;
        Ok((word & 0x9f00001f) | ((value & 3) << 29) | ((value >> 2) << 5))
    } else {
        Ok(word)
    }
}

fn pair_address(words: &[u32], index: usize, pc: u64, register: u32) -> Result<u64, String> {
    if words[index] & 0x9f00001f != 0x90000000 | register
        || words[index + 1] & 0xffc003ff != 0x91000000 | (register << 5) | register
    {
        return Err(refusal(
            "recipe-address-pair",
            "ADRP/ADD register pair mismatch",
        ));
    }
    target(
        adrp(words[index], pc + index as u64 * 4)?,
        ((words[index + 1] >> 10) & 0xfff) as i64,
    )
}

fn encode_adrp(pc: u64, address: u64, register: u32) -> Result<u32, String> {
    let delta = (address & !0xfff) as i128 - (pc & !0xfff) as i128;
    let pages = delta / 4096;
    if !(-(1i128 << 20)..(1i128 << 20)).contains(&pages) {
        return Err(refusal(
            "recipe-adrp-range",
            "CFString exceeds ADRP immediate range",
        ));
    }
    let value = pages as u32 & 0x1fffff;
    Ok(0x90000000 | register | ((value & 3) << 29) | ((value >> 2) << 5))
}

fn skip_tcon_key(data: &[u8], image: &MachO) -> Result<u64, String> {
    let mut found = Vec::new();
    for section in image
        .sections
        .iter()
        .filter(|section| section.name == "__cfstring")
    {
        if section.size % 32 != 0 {
            return Err(refusal(
                "recipe-cfstring",
                "CFString section length is not aligned",
            ));
        }
        for relative in (0..usize64(section.size)?).step_by(32) {
            let address = section.address + relative as u64;
            let offset = image.offset(address, 32)?;
            if le64(data, offset + 8)? == 0x7c8
                && le64(data, offset + 24)? == 10
                && image.cfstring(data, address, b"SkipTCONFW").is_ok()
            {
                found.push(address);
            }
        }
    }
    if found.len() != 1 {
        return Err(refusal(
            "recipe-skip-key",
            format!(
                "expected one validated SkipTCONFW CFString, found {}",
                found.len()
            ),
        ));
    }
    Ok(found[0])
}

fn validate(data: &[u8], image: &MachO, pc: u64, words: &[u32]) -> Result<(), String> {
    if words[0] & 0xfc000000 != 0x94000000
        || words[1] & 0xff00001f != 0x34000000
        || words[4] != 0xaa1503e0
        || words[5] & 0xfc000000 != 0x94000000
        || words[6] & 0x9f00001f != 0x90000008
        || words[7] & 0xffc003ff != 0xf9400108
        || words[8] != 0xf9400108
        || words[9] != 0xeb08001f
        || words[10] & 0xff00001f != 0x54000000
    {
        return Err(refusal(
            "recipe-control-flow",
            "legacy gate and false comparison instruction sequence mismatch",
        ));
    }
    let legacy = branch(words[0], pc)?;
    let offset = image.offset(legacy, 20)?;
    let mode = (0..5)
        .map(|i| le32(data, offset + i * 4))
        .collect::<Result<Vec<_>, _>>()?;
    if mode[0] & 0x9f00001f != 0x90000008
        || mode[1] & 0xffc003ff != 0xb9400108
        || mode[2..] != [0x7100091f, 0x1a9f17e0, 0xd65f03c0]
    {
        return Err(refusal(
            "recipe-legacy-mode",
            "legacy helper must return restore mode equal to 2",
        ));
    }
    let skip = conditional(words[1], pc + 4)?;
    let done = conditional(words[10], pc + 40)?;
    if skip != pc + 92 || done <= skip + 48 {
        return Err(refusal(
            "recipe-targets",
            "skip and successful return targets disagree",
        ));
    }
    let forced_offset = image.offset(pc + 76, 16)?;
    let forced = (0..4)
        .map(|i| le32(data, forced_offset + i * 4))
        .collect::<Result<Vec<_>, _>>()?;
    if forced[0] != 0x910062f6 || forced[3] != 0xf90067e8 {
        return Err(refusal(
            "recipe-force-continuation",
            "forced path must replace scratch registers before use",
        ));
    }
    pair_address(&forced, 1, pc + 76, 8)?;
    let skip_offset = image.offset(skip, 48)?;
    let continuation = (0..12)
        .map(|i| le32(data, skip_offset + i * 4))
        .collect::<Result<Vec<_>, _>>()?;
    if continuation[..7]
        != [
            0x6f00e400, 0xad0483e0, 0xad0383e0, 0xad0283e0, 0xad0183e0, 0x3d800be0, 0xf90002df,
        ]
        || continuation[9] != 0x910083e1
        || continuation[10] != 0xaa1403e0
        || continuation[11] & 0xfc000000 != 0x94000000
    {
        return Err(refusal(
            "recipe-scratch-liveness",
            "skip continuation must replace call arguments before use",
        ));
    }
    pair_address(&continuation, 7, skip, 20)?;
    image.imported(data, branch(continuation[11], skip + 44)?, true, "_stat")?;
    let done_offset = image.offset(done, 8)?;
    if le32(data, done_offset)? != 0x52800020
        || le32(data, done_offset + 4)? & 0xffe00fff != 0xf84003a8
    {
        return Err(refusal(
            "recipe-return",
            "false flag must reach successful return",
        ));
    }
    image.cfstring(data, pair_address(words, 2, pc, 1)?, b"Update TCON FW")?;
    image.imported(
        data,
        branch(words[5], pc + 20)?,
        true,
        "_CFDictionaryGetValue",
    )?;
    let false_pointer = target(
        adrp(words[6], pc + 24)?,
        (((words[7] >> 10) & 0xfff) * 8) as i64,
    )?;
    image.imported(data, false_pointer, false, "_kCFBooleanFalse")?;
    if words[11] & 0xff00001f != 0xb4000014
        || words[12] != 0xf9400680
        || words[13] & 0xff00001f != 0xb4000000
        || words[16] != 0x52800002
        || words[17] & 0xfc000000 != 0x94000000
        || words[18] & 0xff00001f != 0x34000000
        || conditional(words[11], pc + 44)? != skip
        || conditional(words[13], pc + 52)? != skip
        || conditional(words[18], pc + 72)? != skip
    {
        return Err(refusal(
            "recipe-force-gate",
            "ForceTCONFW control flow mismatch",
        ));
    }
    image.cfstring(data, pair_address(words, 14, pc, 1)?, b"ForceTCONFW")?;
    image.imported(
        data,
        branch(words[17], pc + 68)?,
        true,
        "_AMSupportCFDictionaryGetBoolean",
    )?;
    Ok(())
}

fn validate_allowlist(data: &[u8], image: &MachO, pc: u64, words: &[u32]) -> Result<(), String> {
    if words[0] & 0x9f00001f != 0x90000003
        || words[1] & 0xffc003ff != 0xf9400063
        || words[2..5] != [0x9100c3e1, 0xaa1403e0, 0x52800382]
        || words[5] & 0xfc000000 != 0x94000000
        || words[6] & 0xff00001f != 0xb4000000
        || words[7] != 0xaa0003f5
        || words[8] & 0xfc000000 != 0x94000000
        || words[9] != 0xaa0003e2
        || words[12..17] != [0xdac123f0, 0xaa1003e3, 0x910043e4, 0xaa1503e0, 0xd2800001]
        || words[17] & 0xfc000000 != 0x94000000
        || words[18] & 0xfc000000 != 0x14000000
    {
        return Err(refusal(
            "recipe-allowlist-layout",
            "restore option array or callback instruction sequence mismatch",
        ));
    }
    let callback = pair_address(words, 10, pc, 16)?;
    let callback_offset = image.offset(callback, 0x68)?;
    if le32(data, callback_offset)? != 0xd503237f {
        return Err(refusal(
            "recipe-allowlist-callback",
            "key-path callback entry mismatch",
        ));
    }
    image.imported(
        data,
        branch(le32(data, callback_offset + 0x40)?, callback + 0x40)?,
        true,
        "_AMSupportGetValueForKeyPathInDict",
    )?;
    image.imported(
        data,
        branch(le32(data, callback_offset + 0x64)?, callback + 0x64)?,
        true,
        "_AMSupportCopySetValueForKeyPathInDict",
    )?;
    image.imported(data, branch(words[5], pc + 20)?, true, "_CFArrayCreate")?;
    image.imported(data, branch(words[8], pc + 32)?, true, "_CFArrayGetCount")?;
    image.imported(
        data,
        branch(words[17], pc + 68)?,
        true,
        "_CFArrayApplyFunction",
    )?;
    let before = image.offset(pc - 44, 44)?;
    if le32(data, before)? != 0xf90017ff
        || le32(data, before + 32)? & 0xfc000000 != 0x94000000
        || le32(data, before + 36)? != 0xf9000fe0
        || le32(data, before + 40)? & 0xff00001f != 0xb4000000
        || conditional(le32(data, before + 40)?, pc - 4)? != pc + 76
    {
        return Err(refusal(
            "recipe-allowlist-context",
            "error slot or restore option lookup mismatch",
        ));
    }
    image.imported(
        data,
        branch(le32(data, before + 32)?, pc - 12)?,
        true,
        "_CFDictionaryGetValue",
    )?;
    if conditional(words[6], pc + 24)? <= pc + 76 || branch(words[18], pc + 72)? != pc + 80 {
        return Err(refusal(
            "recipe-allowlist-targets",
            "array failure or continuation target mismatch",
        ));
    }
    Ok(())
}

fn incoming_branch(data: &[u8], text: &Section, pc: u64, size: u64) -> Result<(), String> {
    let length = usize64(text.size)?;
    for relative in (0..length.saturating_sub(3)).step_by(4) {
        let address = text.address + relative as u64;
        if address >= pc && address < pc + size {
            continue;
        }
        let word = le32(data, text.offset + relative)?;
        let destination = if word & 0x7c000000 == 0x14000000 {
            Some(branch(word, address)?)
        } else if word & 0xff000010 == 0x54000000 || word & 0x7e000000 == 0x34000000 {
            Some(conditional(word, address)?)
        } else if word & 0x7e000000 == 0x36000000 {
            Some(target(address, signed((word >> 5) & 0x3fff, 14) * 4)?)
        } else {
            None
        };
        if destination.is_some_and(|target| target > pc && target < pc + size) {
            return Err(refusal(
                "recipe-incoming-branch",
                format!("branch at {address:#x} enters rewritten instructions"),
            ));
        }
    }
    Ok(())
}

fn apply_allowlist(
    data: &[u8],
    image: &MachO,
    output: &mut [u8],
    text: &Section,
) -> Result<(), String> {
    let length = usize64(text.size)?;
    let mut candidates = Vec::new();
    let mut rejected = None;
    for relative in (0..length.saturating_sub(75)).step_by(4) {
        let offset = text.offset + relative;
        if le32(data, offset + 8)? != 0x9100c3e1 || le32(data, offset + 16)? != 0x52800382 {
            continue;
        }
        let words = (0..19)
            .map(|i| le32(data, offset + i * 4))
            .collect::<Result<Vec<_>, _>>()?;
        let pc = text.address + relative as u64;
        match validate_allowlist(data, image, pc, &words) {
            Ok(()) => candidates.push((offset, pc, words)),
            Err(error) => rejected = Some(error),
        }
    }
    if candidates.len() != 1 {
        return Err(refusal(
            "recipe-allowlist-unique",
            format!(
                "expected one validated restore option allowlist, found {}; {}",
                candidates.len(),
                rejected.unwrap_or_else(|| "semantic pattern not found".into())
            ),
        ));
    }
    let (offset, pc, words) = &candidates[0];
    incoming_branch(data, text, *pc, 76)?;
    let key = skip_tcon_key(data, image)?;
    let callback = pair_address(words, 10, *pc, 16)?;
    let relocated =
        |old: usize, new: usize| relocate(words[old], *pc + old as u64 * 4, *pc + new as u64 * 4);
    let rewritten = [
        encode_adrp(*pc, key, 8)?,
        0x91000108 | (((key & 0xfff) as u32) << 10),
        0xf90017e8,
        relocated(0, 3)?,
        words[1],
        0x9100a3e1,
        words[3],
        0x528003a2,
        relocated(5, 8)?,
        relocated(6, 9)?,
        words[7],
        0x528003a2,
        encode_adrp(*pc + 48, callback, 3)?,
        0x91000063 | (((callback & 0xfff) as u32) << 10),
        0xdac123e3,
        words[14],
        words[16],
        words[17],
        words[18],
    ];
    for (index, word) in rewritten.into_iter().enumerate() {
        output[offset + index * 4..offset + index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(())
}

pub(super) fn apply(data: &[u8], image: &MachO, output: &mut [u8]) -> Result<(), String> {
    let text = image
        .sections
        .iter()
        .filter(|section| section.name == "__text")
        .collect::<Vec<_>>();
    if text.len() != 1 {
        return Err(refusal(
            "recipe-text",
            format!("expected one __text section, found {}", text.len()),
        ));
    }
    let text = text[0];
    let length = usize64(text.size)?;
    let mut candidates = Vec::new();
    let mut rejected = None;
    for relative in (0..length.saturating_sub(75)).step_by(4) {
        let offset = text.offset + relative;
        if le32(data, offset + 16)? != 0xaa1503e0 || le32(data, offset + 36)? != 0xeb08001f {
            continue;
        }
        let words = (0..19)
            .map(|i| le32(data, offset + i * 4))
            .collect::<Result<Vec<_>, _>>()?;
        let pc = text.address + relative as u64;
        match validate(data, image, pc, &words) {
            Ok(()) => candidates.push((offset, pc, words)),
            Err(error) => rejected = Some(error),
        }
    }
    if candidates.len() != 1 {
        return Err(refusal(
            "recipe-unique",
            format!(
                "expected one validated update_TCON gate, found {}; {}",
                candidates.len(),
                rejected.unwrap_or_else(|| "semantic pattern not found".into())
            ),
        ));
    }
    let (offset, pc, words) = &candidates[0];
    incoming_branch(data, text, *pc, 44)?;
    for (new_index, old_index) in (2..11).chain(0..2).enumerate() {
        let word = relocate(
            words[old_index],
            *pc + old_index as u64 * 4,
            *pc + new_index as u64 * 4,
        )?;
        let location = offset + new_index * 4;
        output[location..location + 4].copy_from_slice(&word.to_le_bytes());
    }
    apply_allowlist(data, image, output, text)
}

#[cfg(test)]
mod tests {
    use super::super::{code_signature, prepare_skip_tcon, trustcache};
    use super::*;

    const BASE: u64 = 0x100000000;
    const GATE: usize = 0x1000;
    const ALLOWLIST: usize = 0x1400;

    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn adrp_word(register: u32, pc: u64, destination: u64) -> u32 {
        let delta = ((destination & !0xfff) as i64 - (pc & !0xfff) as i64) / 4096;
        let value = delta as u32 & 0x1fffff;
        0x90000000 | register | ((value & 3) << 29) | ((value >> 2) << 5)
    }

    fn add_word(register: u32, destination: usize) -> u32 {
        0x91000000 | (((destination & 0xfff) as u32) << 10) | (register << 5) | register
    }

    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; 0x4000];
        for (offset, value) in [(0, 0xfeedfacf), (4, 0x0100000c), (8, 2), (12, 2), (16, 5)] {
            put32(&mut data, offset, value);
        }
        let sections = [
            ("__text", 0x1000usize, 0x900usize, 0x80000400u32, 0u32, 0u32),
            ("__auth_stubs", 0x2000, 0x80, 8, 0, 16),
            ("__cfstring", 0x2800, 0x60, 0, 0, 0),
            ("__cstring", 0x2900, 0x60, 2, 0, 0),
            ("__got", 0x3000, 8, 6, 8, 0),
        ];
        let segment_size = 72 + sections.len() * 80;
        let mut cursor = 32;
        put32(&mut data, cursor, 0x19);
        put32(&mut data, cursor + 4, segment_size as u32);
        data[cursor + 8..cursor + 14].copy_from_slice(b"__TEXT");
        put64(&mut data, cursor + 24, BASE);
        put64(&mut data, cursor + 32, 0x4000);
        put64(&mut data, cursor + 48, 0x4000);
        put32(&mut data, cursor + 64, sections.len() as u32);
        for (index, (name, offset, length, flags, reserved1, reserved2)) in
            sections.into_iter().enumerate()
        {
            let entry = cursor + 72 + index * 80;
            data[entry..entry + name.len()].copy_from_slice(name.as_bytes());
            data[entry + 16..entry + 22].copy_from_slice(b"__TEXT");
            put64(&mut data, entry + 32, BASE + offset as u64);
            put64(&mut data, entry + 40, length as u64);
            put32(&mut data, entry + 48, offset as u32);
            put32(&mut data, entry + 64, flags);
            put32(&mut data, entry + 68, reserved1);
            put32(&mut data, entry + 72, reserved2);
        }
        cursor += segment_size;
        put32(&mut data, cursor, 2);
        put32(&mut data, cursor + 4, 24);
        for (index, value) in [0x3100u32, 9, 0x3200, 0x400].into_iter().enumerate() {
            put32(&mut data, cursor + 8 + index * 4, value);
        }
        cursor += 24;
        put32(&mut data, cursor, 0xb);
        put32(&mut data, cursor + 4, 80);
        put32(&mut data, cursor + 56, 0x31c0);
        put32(&mut data, cursor + 60, 9);
        cursor += 80;
        put32(&mut data, cursor, 0x80000034);
        put32(&mut data, cursor + 4, 16);
        put32(&mut data, cursor + 8, 0x3600);
        put32(&mut data, cursor + 12, 64);
        cursor += 16;
        put32(&mut data, cursor, 0x1d);
        put32(&mut data, cursor + 4, 16);
        put32(&mut data, cursor + 8, 0x4000);
        put32(&mut data, cursor + 12, 596);
        cursor += 16;
        put32(&mut data, 20, (cursor - 32) as u32);
        let imports = [
            "_CFDictionaryGetValue",
            "_AMSupportCFDictionaryGetBoolean",
            "_stat",
            "_CFArrayCreate",
            "_CFArrayGetCount",
            "_CFArrayApplyFunction",
            "_AMSupportGetValueForKeyPathInDict",
            "_AMSupportCopySetValueForKeyPathInDict",
            "_kCFBooleanFalse",
        ];
        let mut string_cursor = 0x3201;
        for (index, symbol) in imports.into_iter().enumerate() {
            put32(
                &mut data,
                0x3100 + index * 16,
                (string_cursor - 0x3200) as u32,
            );
            data[0x3104 + index * 16] = 1;
            data[string_cursor..string_cursor + symbol.len()].copy_from_slice(symbol.as_bytes());
            string_cursor += symbol.len() + 1;
            put32(&mut data, 0x31c0 + index * 4, index as u32);
        }
        for (offset, string_offset, text, next) in [
            (0x2800usize, 0x2900usize, b"Update TCON FW".as_slice(), 4u64),
            (0x2820, 0x2920, b"ForceTCONFW".as_slice(), 4),
            (0x2840, 0x2940, b"SkipTCONFW".as_slice(), 0),
        ] {
            put64(&mut data, offset + 8, 0x7c8);
            put64(&mut data, offset + 16, string_offset as u64 | (next << 51));
            put64(&mut data, offset + 24, text.len() as u64);
            data[string_offset..string_offset + text.len()].copy_from_slice(text);
        }
        put32(&mut data, 0x3604, 28);
        put32(&mut data, 0x361c, 1);
        put32(&mut data, 0x3620, 8);
        put32(&mut data, 0x3624, 28);
        data[0x3628..0x362a].copy_from_slice(&4096u16.to_le_bytes());
        data[0x362a..0x362c].copy_from_slice(&12u16.to_le_bytes());
        data[0x3638..0x363a].copy_from_slice(&3u16.to_le_bytes());
        data[0x363a..0x363e].copy_from_slice(&[0xff, 0xff, 0xff, 0xff]);
        data[0x363e..0x3640].copy_from_slice(&0x810u16.to_le_bytes());
        let pc = BASE + GATE as u64;
        let jump = |word: u32, index: u64, destination: u64, bits: u32, shift: u32| {
            encode_delta(word, pc + index * 4, BASE + destination, bits, shift).unwrap()
        };
        let words = [
            jump(0x94000000, 0, 0x1800, 26, 0),
            jump(0x34000000, 1, 0x105c, 19, 5),
            adrp_word(1, pc + 8, BASE + 0x2800),
            add_word(1, 0x2800),
            0xaa1503e0,
            jump(0x94000000, 5, 0x2000, 26, 0),
            adrp_word(8, pc + 24, BASE + 0x3000),
            0xf9400108,
            0xf9400108,
            0xeb08001f,
            jump(0x54000000, 10, 0x10c0, 19, 5),
            jump(0xb4000014, 11, 0x105c, 19, 5),
            0xf9400680,
            jump(0xb4000000, 13, 0x105c, 19, 5),
            adrp_word(1, pc + 56, BASE + 0x2820),
            add_word(1, 0x2820),
            0x52800002,
            jump(0x94000000, 17, 0x2010, 26, 0),
            jump(0x34000000, 18, 0x105c, 19, 5),
        ];
        for (index, word) in words.into_iter().enumerate() {
            put32(&mut data, GATE + index * 4, word);
        }
        for (index, word) in [
            0x910062f6,
            adrp_word(8, BASE + 0x1050, BASE + 0x2920),
            add_word(8, 0x2920),
            0xf90067e8,
        ]
        .into_iter()
        .enumerate()
        {
            put32(&mut data, 0x104c + index * 4, word);
        }
        let continuation = [
            0x6f00e400,
            0xad0483e0,
            0xad0383e0,
            0xad0283e0,
            0xad0183e0,
            0x3d800be0,
            0xf90002df,
            adrp_word(20, BASE + 0x1078, BASE + 0x2920),
            add_word(20, 0x2920),
            0x910083e1,
            0xaa1403e0,
            encode_delta(0x94000000, BASE + 0x1088, BASE + 0x2020, 26, 0).unwrap(),
        ];
        for (index, word) in continuation.into_iter().enumerate() {
            put32(&mut data, 0x105c + index * 4, word);
        }
        put32(&mut data, 0x10c0, 0x52800020);
        put32(&mut data, 0x10c4, 0xf85c83a8);
        for (index, word) in [
            adrp_word(8, BASE + 0x1800, BASE + 0x3800),
            0xb9480108,
            0x7100091f,
            0x1a9f17e0,
            0xd65f03c0,
        ]
        .into_iter()
        .enumerate()
        {
            put32(&mut data, 0x1800 + index * 4, word);
        }
        let list_pc = BASE + ALLOWLIST as u64;
        let list_jump = |word: u32, index: u64, destination: u64, bits: u32, shift: u32| {
            encode_delta(word, list_pc + index * 4, BASE + destination, bits, shift).unwrap()
        };
        put32(&mut data, ALLOWLIST - 44, 0xf90017ff);
        put32(
            &mut data,
            ALLOWLIST - 12,
            encode_delta(0x94000000, list_pc - 12, BASE + 0x2000, 26, 0).unwrap(),
        );
        put32(&mut data, ALLOWLIST - 8, 0xf9000fe0);
        put32(
            &mut data,
            ALLOWLIST - 4,
            encode_delta(0xb4000000, list_pc - 4, list_pc + 76, 19, 5).unwrap(),
        );
        let list = [
            adrp_word(3, list_pc, BASE + 0x3000),
            0xf9400063,
            0x9100c3e1,
            0xaa1403e0,
            0x52800382,
            list_jump(0x94000000, 5, 0x2030, 26, 0),
            list_jump(0xb4000000, 6, 0x1500, 19, 5),
            0xaa0003f5,
            list_jump(0x94000000, 8, 0x2040, 26, 0),
            0xaa0003e2,
            adrp_word(16, list_pc + 40, BASE + 0x1850),
            add_word(16, 0x1850),
            0xdac123f0,
            0xaa1003e3,
            0x910043e4,
            0xaa1503e0,
            0xd2800001,
            list_jump(0x94000000, 17, 0x2050, 26, 0),
            list_jump(0x14000000, 18, 0x1450, 26, 0),
        ];
        for (index, word) in list.into_iter().enumerate() {
            put32(&mut data, ALLOWLIST + index * 4, word);
        }
        put32(&mut data, ALLOWLIST + 76, 0xd2800015);
        put32(&mut data, 0x1850, 0xd503237f);
        put32(
            &mut data,
            0x1890,
            encode_delta(0x94000000, BASE + 0x1890, BASE + 0x2060, 26, 0).unwrap(),
        );
        put32(
            &mut data,
            0x18b4,
            encode_delta(0x94000000, BASE + 0x18b4, BASE + 0x2070, 26, 0).unwrap(),
        );
        code_signature::tests::fixture(data).0
    }

    #[derive(Debug, PartialEq, Eq)]
    enum GateResult {
        ContinueTcon,
        ForceGate,
        Success,
    }

    fn execute_gate(data: &[u8], mode: u32, flag: Option<bool>) -> GateResult {
        let mut pc = BASE + GATE as u64;
        let mut value = 0;
        let mut equal = false;
        for _ in 0..20 {
            if pc == BASE + 0x105c {
                return GateResult::ContinueTcon;
            }
            if pc == BASE + 0x10c0 {
                return GateResult::Success;
            }
            if pc == BASE + GATE as u64 + 44 {
                return GateResult::ForceGate;
            }
            let word = le32(data, (pc - BASE) as usize).unwrap();
            if word & 0xfc000000 == 0x94000000 {
                value = match branch(word, pc).unwrap() - BASE {
                    0x1800 => u32::from(mode == 2),
                    0x2000 => match flag {
                        Some(false) => 0,
                        Some(true) => 1,
                        None => 2,
                    },
                    destination => panic!("unexpected call {destination:#x}"),
                };
            } else if word & 0xff00001f == 0x34000000 && value == 0 {
                pc = conditional(word, pc).unwrap();
                continue;
            } else if word == 0xeb08001f {
                equal = value == 0;
            } else if word & 0xff00001f == 0x54000000 && equal {
                pc = conditional(word, pc).unwrap();
                continue;
            }
            pc += 4;
        }
        panic!("gate execution did not reach a validated target")
    }

    #[test]
    fn prepared_patch_honors_false_in_both_modes_and_preserves_force_gate() {
        let original = fixture();
        let image = MachO::parse(&original).unwrap();
        let signature =
            code_signature::ValidatedSignature::parse(&original, image.signature.clone()).unwrap();
        let mut unchanged = original.clone();
        let (old, _) = signature.rehash(&original, &mut unchanged).unwrap();
        let cache = trustcache::tests::fixture(&[old]);
        let prepared = prepare_skip_tcon(&original, &cache).unwrap();
        let cases = [
            (1, Some(false), GateResult::Success),
            (1, Some(true), GateResult::ContinueTcon),
            (1, None, GateResult::ContinueTcon),
            (2, Some(false), GateResult::Success),
            (2, Some(true), GateResult::ForceGate),
            (2, None, GateResult::ForceGate),
        ];
        for (mode, flag, expected) in cases {
            assert_eq!(execute_gate(&prepared.executable, mode, flag), expected);
        }
        assert_eq!(
            execute_gate(&original, 1, Some(false)),
            GateResult::ContinueTcon
        );
        assert_eq!(execute_gate(&original, 2, Some(false)), GateResult::Success);
        assert_eq!(
            &prepared.executable[GATE + 44..ALLOWLIST],
            &original[GATE + 44..ALLOWLIST]
        );
        assert_eq!(
            &prepared.executable[ALLOWLIST + 76..image.signature.start],
            &original[ALLOWLIST + 76..image.signature.start]
        );
        assert_eq!(&prepared.executable[..GATE], &original[..GATE]);
        assert_eq!(prepared.old_cdhash, old);
        assert_eq!(
            prepared.trustcache_im4p,
            trustcache::tests::fixture(&[prepared.new_cdhash])
        );
        code_signature::ValidatedSignature::parse(&prepared.executable, image.signature).unwrap();
    }

    #[test]
    fn prepared_patch_admits_skip_key_with_all_original_options() {
        let original = fixture();
        let image = MachO::parse(&original).unwrap();
        let signature =
            code_signature::ValidatedSignature::parse(&original, image.signature.clone()).unwrap();
        let mut unchanged = original.clone();
        let (old, _) = signature.rehash(&original, &mut unchanged).unwrap();
        let prepared = prepare_skip_tcon(&original, &trustcache::tests::fixture(&[old])).unwrap();
        let pc = BASE + ALLOWLIST as u64;
        let words = (0..19)
            .map(|index| le32(&prepared.executable, ALLOWLIST + index * 4).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pair_address(&words, 0, pc, 8).unwrap(), BASE + 0x2840);
        assert_eq!(words[2], 0xf90017e8);
        assert_eq!(words[5], 0x9100a3e1);
        assert_eq!(words[7], 0x528003a2);
        assert_eq!(branch(words[8], pc + 32).unwrap(), BASE + 0x2030);
        assert_eq!(conditional(words[9], pc + 36).unwrap(), BASE + 0x1500);
        assert_eq!(words[11], 0x528003a2);
        assert_eq!(pair_address(&words, 12, pc, 3).unwrap(), BASE + 0x1850);
        assert_eq!(branch(words[17], pc + 68).unwrap(), BASE + 0x2050);
        assert_eq!(
            &prepared.executable[ALLOWLIST - 44..ALLOWLIST],
            &original[ALLOWLIST - 44..ALLOWLIST]
        );
        assert_eq!(
            &prepared.executable[ALLOWLIST + 76..image.signature.start],
            &original[ALLOWLIST + 76..image.signature.start]
        );
        assert_eq!(
            le32(&prepared.executable, ALLOWLIST + 76).unwrap(),
            0xd2800015
        );
    }

    #[test]
    fn relocation_reencodes_adrp_when_gate_crosses_page_boundary() {
        let original = adrp_word(1, BASE + 0x1000, BASE + 0x7000);
        let relocated = relocate(original, BASE + 0x1000, BASE + 0xff8).unwrap();
        assert_eq!(adrp(relocated, BASE + 0xff8).unwrap(), BASE + 0x7000);
        let call = encode_delta(0x94000000, BASE + 0x1000, BASE + 0x800, 26, 0).unwrap();
        let moved = relocate(call, BASE + 0x1000, BASE + 0x1024).unwrap();
        assert_eq!(branch(moved, BASE + 0x1024).unwrap(), BASE + 0x800);
    }

    #[test]
    fn changed_semantic_key_records_named_refusal() {
        let original = fixture();
        let mut code = original[..0x4000].to_vec();
        code[0x2900] = b'X';
        let signed = code_signature::tests::fixture(code).0;
        let image = MachO::parse(&signed).unwrap();
        let mut output = signed.clone();
        let error = apply(&signed, &image, &mut output).unwrap_err();
        assert!(error.starts_with("skip-tcon-recipe-unique:"));
        assert!(error.contains("skip-tcon-recipe-cfstring:"));
    }
}
