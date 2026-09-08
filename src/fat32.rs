use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

const FAT_EPOCH_DATE: u16 = 0x0021; // 1980-01-01, the FAT epoch.
const LFN_CHARS_PER_ENTRY: usize = 13;
const DIR_ENTRY_SIZE: usize = 32;
const SHORT_NAME_CHARSET_EXTRA: &str = "!#$%&'()-@^_`{}~";

// Real-filesystem traversal and symlink protections. Do not weaken these.

fn checked_path(root: &Path, name: &str, create_parents: bool) -> Result<PathBuf, String> {
    let mut path = root.to_path_buf();
    let components: Vec<_> = Path::new(name).components().collect();
    for (i, component) in components.iter().enumerate() {
        let std::path::Component::Normal(component) = component else {
            return Err("Invalid EFI boot path".into());
        };
        path.push(component);
        let last = i + 1 == components.len();
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!(
                    "Refusing symbolic link in EFI boot path: {}",
                    path.display()
                ));
            }
            Ok(meta) if !last && !meta.is_dir() => {
                return Err(format!(
                    "EFI boot path parent is not a directory: {}",
                    path.display()
                ));
            }
            Ok(meta) if last && !meta.is_file() => {
                return Err(format!(
                    "EFI boot target is not a regular file: {}",
                    path.display()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && create_parents => {
                if !last {
                    fs::create_dir(&path).map_err(|e| e.to_string())?;
                }
            }
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Ok(path)
}

fn write(root: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let path = checked_path(root, name, true)?;
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    std::io::Write::write_all(&mut file, bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())
}

fn validate_efi_geometry(part_bytes: u64, sector_size: u32) -> Result<(), String> {
    if ![512, 1024, 2048, 4096].contains(&sector_size)
        || part_bytes == 0
        || !part_bytes.is_multiple_of(u64::from(sector_size))
    {
        return Err("EFI size must be a nonzero multiple of a supported FAT sector size".into());
    }
    Ok(())
}

fn efi_sector_size(container: &[u8]) -> Result<u32, String> {
    if container.len() < 512 || container[510..512] != [0x55, 0xaa] {
        return Err("EFI filesystem has no valid FAT boot sector".into());
    }
    let sector_size = u32::from(u16::from_le_bytes([container[11], container[12]]));
    validate_efi_geometry(container.len() as u64, sector_size)?;
    Ok(sector_size)
}

fn validate_efi_files(files: &[(String, Vec<u8>)]) -> Result<(), String> {
    let mut names = HashSet::new();
    for (name, _) in files {
        if name.is_empty()
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.ends_with([' ', '.'])
                    || part
                        .chars()
                        .any(|c| c.is_control() || "\\:*?\"<>|".contains(c))
            })
        {
            return Err(format!("Invalid EFI file path: {name}"));
        }
        if !names.insert(name.to_lowercase()) {
            return Err(format!("Duplicate EFI file path: {name}"));
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FatType {
    Fat16,
    Fat32,
}

#[derive(Clone, Copy, Debug)]
struct Layout {
    fat_type: FatType,
    bytes_per_sector: u32,
    sectors_per_cluster: u32,
    reserved_sectors: u32,
    num_fats: u32,
    root_entry_count: u32,
    total_sectors: u64,
    hidden_sectors: u32,
    fat_size_sectors: u32,
}

impl Layout {
    fn root_dir_sectors(&self) -> u64 {
        (u64::from(self.root_entry_count) * 32).div_ceil(u64::from(self.bytes_per_sector))
    }
    fn first_fat_sector(&self) -> u64 {
        u64::from(self.reserved_sectors)
    }
    fn first_root_dir_sector(&self) -> u64 {
        self.first_fat_sector() + u64::from(self.num_fats) * u64::from(self.fat_size_sectors)
    }
    fn first_data_sector(&self) -> u64 {
        self.first_root_dir_sector() + self.root_dir_sectors()
    }
    fn bytes_per_cluster(&self) -> u64 {
        u64::from(self.bytes_per_sector) * u64::from(self.sectors_per_cluster)
    }
    fn cluster_offset(&self, cluster: u32) -> u64 {
        (self.first_data_sector() + (u64::from(cluster) - 2) * u64::from(self.sectors_per_cluster))
            * u64::from(self.bytes_per_sector)
    }
    fn data_sectors(&self) -> u64 {
        self.total_sectors.saturating_sub(self.first_data_sector())
    }
    fn max_clusters(&self) -> u64 {
        self.data_sectors() / u64::from(self.sectors_per_cluster)
    }
    fn fat_region_len(&self) -> usize {
        self.fat_size_sectors as usize * self.bytes_per_sector as usize
    }
}

fn fat_entry_size(fat_type: FatType) -> usize {
    match fat_type {
        FatType::Fat16 => 2,
        FatType::Fat32 => 4,
    }
}

fn fat_eoc(fat_type: FatType) -> u32 {
    match fat_type {
        FatType::Fat16 => 0xFFFF,
        FatType::Fat32 => 0x0FFF_FFFF,
    }
}

fn fat_is_eoc(fat_type: FatType, value: u32) -> bool {
    match fat_type {
        FatType::Fat16 => value >= 0xFFF8,
        FatType::Fat32 => value >= 0x0FFF_FFF8,
    }
}

fn fat_get(fat: &[u8], index: u32, fat_type: FatType) -> u32 {
    let sz = fat_entry_size(fat_type);
    let off = index as usize * sz;
    match fat_type {
        FatType::Fat16 => u32::from(u16::from_le_bytes(fat[off..off + 2].try_into().unwrap())),
        FatType::Fat32 => u32::from_le_bytes(fat[off..off + 4].try_into().unwrap()) & 0x0FFF_FFFF,
    }
}

fn fat_set(fat: &mut [u8], index: u32, value: u32, fat_type: FatType) {
    let sz = fat_entry_size(fat_type);
    let off = index as usize * sz;
    match fat_type {
        FatType::Fat16 => fat[off..off + 2].copy_from_slice(&(value as u16).to_le_bytes()),
        FatType::Fat32 => fat[off..off + 4].copy_from_slice(&(value & 0x0FFF_FFFF).to_le_bytes()),
    }
}

fn choose_spc_fat32(total_sectors: u64, bytes_per_sector: u32) -> u32 {
    let total_bytes = total_sectors.saturating_mul(u64::from(bytes_per_sector));
    let gb = 1024u64 * 1024 * 1024;
    let target_cluster_bytes: u64 = if total_bytes < 64 * 1024 * 1024 {
        512
    } else if total_bytes < 128 * 1024 * 1024 {
        1024
    } else if total_bytes < 256 * 1024 * 1024 {
        2048
    } else if total_bytes < 8 * gb {
        4096
    } else if total_bytes < 16 * gb {
        8192
    } else if total_bytes < 32 * gb {
        16384
    } else {
        32768
    };
    let raw = (target_cluster_bytes / u64::from(bytes_per_sector)).max(1);
    let mut spc = 1u64;
    while spc * 2 <= raw && spc < 128 {
        spc *= 2;
    }
    spc as u32
}

fn compute_fat_size(layout: &Layout) -> Result<u32, String> {
    let entry_bytes = fat_entry_size(layout.fat_type) as u64;
    let root_dir_sectors = layout.root_dir_sectors();
    let reserved = u64::from(layout.reserved_sectors);
    let num_fats = u64::from(layout.num_fats);
    let spc = u64::from(layout.sectors_per_cluster);
    let bps = u64::from(layout.bytes_per_sector);
    let total = layout.total_sectors;
    let mut fat_size: u64 = 1;
    for _ in 0..64 {
        let overhead = reserved + root_dir_sectors + num_fats * fat_size;
        if overhead >= total {
            return Err("EFI partition is too small for the requested FAT geometry".into());
        }
        let data_sectors = total - overhead;
        let count_of_clusters = data_sectors / spc;
        let entries = count_of_clusters + 2;
        let bytes_needed = entries * entry_bytes;
        let needed = bytes_needed.div_ceil(bps).max(1);
        if needed == fat_size {
            return u32::try_from(fat_size)
                .map_err(|_| "FAT size exceeds addressable range".to_string());
        }
        fat_size = needed;
    }
    u32::try_from(fat_size).map_err(|_| "FAT size exceeds addressable range".to_string())
}

fn write_bpb(image: &mut [u8], layout: &Layout, root_cluster: u32, volume_label: &[u8; 11]) {
    image[0] = 0xEB;
    image[1] = 0x58;
    image[2] = 0x90;
    image[3..11].copy_from_slice(b"RUSTFAT ");
    image[11..13].copy_from_slice(&(layout.bytes_per_sector as u16).to_le_bytes());
    image[13] = layout.sectors_per_cluster as u8;
    image[14..16].copy_from_slice(&(layout.reserved_sectors as u16).to_le_bytes());
    image[16] = layout.num_fats as u8;
    image[17..19].copy_from_slice(&(layout.root_entry_count as u16).to_le_bytes());
    image[19..21].copy_from_slice(&0u16.to_le_bytes());
    image[21] = 0xF8;
    let fat_size16: u16 = if layout.fat_type == FatType::Fat16 {
        layout.fat_size_sectors as u16
    } else {
        0
    };
    image[22..24].copy_from_slice(&fat_size16.to_le_bytes());
    image[24..26].copy_from_slice(&63u16.to_le_bytes());
    image[26..28].copy_from_slice(&255u16.to_le_bytes());
    image[28..32].copy_from_slice(&layout.hidden_sectors.to_le_bytes());
    image[32..36].copy_from_slice(&(layout.total_sectors as u32).to_le_bytes());
    match layout.fat_type {
        FatType::Fat32 => {
            image[36..40].copy_from_slice(&layout.fat_size_sectors.to_le_bytes());
            image[40..42].copy_from_slice(&0u16.to_le_bytes());
            image[42..44].copy_from_slice(&0u16.to_le_bytes());
            image[44..48].copy_from_slice(&root_cluster.to_le_bytes());
            image[48..50].copy_from_slice(&1u16.to_le_bytes());
            image[50..52].copy_from_slice(&6u16.to_le_bytes());
            image[64] = 0x80;
            image[65] = 0;
            image[66] = 0x29;
            image[67..71].copy_from_slice(&0x5253_5546u32.to_le_bytes());
            image[71..82].copy_from_slice(volume_label);
            image[82..90].copy_from_slice(b"FAT32   ");
        }
        FatType::Fat16 => {
            image[36] = 0x80;
            image[37] = 0;
            image[38] = 0x29;
            image[39..43].copy_from_slice(&0x5253_5546u32.to_le_bytes());
            image[43..54].copy_from_slice(volume_label);
            image[54..62].copy_from_slice(b"FAT16   ");
        }
    }
    image[510] = 0x55;
    image[511] = 0xaa;
}

fn write_fsinfo(sector: &mut [u8], free_count: u32, next_free: u32) {
    sector[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
    sector[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
    sector[488..492].copy_from_slice(&free_count.to_le_bytes());
    sector[492..496].copy_from_slice(&next_free.to_le_bytes());
    sector[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
}

fn is_short_safe_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || SHORT_NAME_CHARSET_EXTRA.contains(c)
}

fn short_name_candidate(name: &str) -> Option<[u8; 11]> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii()) {
        return None;
    }
    if name.chars().any(|c| c.is_ascii_lowercase() || c == ' ') {
        return None;
    }
    let (base, ext) = match name.rfind('.') {
        Some(pos) if pos != 0 => (&name[..pos], &name[pos + 1..]),
        Some(_) => return None,
        None => (name, ""),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return None;
    }
    if base.contains('.') || ext.contains('.') {
        return None;
    }
    if !base.chars().all(is_short_safe_char) || !ext.chars().all(is_short_safe_char) {
        return None;
    }
    let mut out = [b' '; 11];
    out[..base.len()].copy_from_slice(base.as_bytes());
    out[8..8 + ext.len()].copy_from_slice(ext.as_bytes());
    Some(out)
}

fn clean_short_component(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| {
            let u = c.to_ascii_uppercase();
            if is_short_safe_char(u) { u } else { '_' }
        })
        .collect()
}

fn make_unique_short_alias(name: &str, used: &mut HashSet<[u8; 11]>) -> Result<[u8; 11], String> {
    let (raw_base, raw_ext) = match name.rfind('.') {
        Some(pos) if pos != 0 => (&name[..pos], &name[pos + 1..]),
        _ => (name, ""),
    };
    let base_clean = clean_short_component(&raw_base.replace('.', ""));
    let base_clean = if base_clean.is_empty() {
        "FILE".to_string()
    } else {
        base_clean
    };
    let ext_clean: String = clean_short_component(raw_ext).chars().take(3).collect();
    for n in 1u32..=999_999 {
        let tail = format!("~{n}");
        let keep = 8usize.saturating_sub(tail.len());
        let base_part: String = base_clean.chars().take(keep).collect();
        let mut out = [b' '; 11];
        let candidate_base = format!("{base_part}{tail}");
        out[..candidate_base.len()].copy_from_slice(candidate_base.as_bytes());
        out[8..8 + ext_clean.len()].copy_from_slice(ext_clean.as_bytes());
        if used.insert(out) {
            return Ok(out);
        }
    }
    Err(format!(
        "Too many colliding short-name aliases in one FAT directory near '{name}'"
    ))
}

fn build_short_and_lfn(
    name: &str,
    used: &mut HashSet<[u8; 11]>,
) -> Result<([u8; 11], bool), String> {
    if let Some(direct) = short_name_candidate(name)
        && used.insert(direct)
    {
        return Ok((direct, false));
    }
    Ok((make_unique_short_alias(name, used)?, true))
}

fn lfn_checksum(short: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &b in short {
        sum = sum.rotate_right(1).wrapping_add(b);
    }
    sum
}

fn build_lfn_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let checksum = lfn_checksum(short);
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut chunks: Vec<[u16; LFN_CHARS_PER_ENTRY]> = Vec::new();
    for chunk in units.chunks(LFN_CHARS_PER_ENTRY) {
        let mut arr = [0xFFFFu16; LFN_CHARS_PER_ENTRY];
        for (i, &u) in chunk.iter().enumerate() {
            arr[i] = u;
        }
        if chunk.len() < LFN_CHARS_PER_ENTRY {
            arr[chunk.len()] = 0x0000;
        }
        chunks.push(arr);
    }
    if chunks.is_empty() {
        chunks.push([0u16; LFN_CHARS_PER_ENTRY]);
    }
    let total = chunks.len();
    let mut entries = Vec::with_capacity(total);
    for (i, chunk) in chunks.iter().enumerate().rev() {
        let seq = (i as u8) + 1;
        let ord = if i == total - 1 { seq | 0x40 } else { seq };
        let mut e = [0u8; 32];
        e[0] = ord;
        for j in 0..5 {
            e[1 + j * 2..3 + j * 2].copy_from_slice(&chunk[j].to_le_bytes());
        }
        e[11] = 0x0F;
        e[12] = 0;
        e[13] = checksum;
        for j in 0..6 {
            e[14 + j * 2..16 + j * 2].copy_from_slice(&chunk[5 + j].to_le_bytes());
        }
        e[26..28].copy_from_slice(&0u16.to_le_bytes());
        for j in 0..2 {
            e[28 + j * 2..30 + j * 2].copy_from_slice(&chunk[11 + j].to_le_bytes());
        }
        entries.push(e);
    }
    entries
}

fn dot_entries(self_cluster: u32, parent_cluster: u32) -> Vec<u8> {
    let mut raw = Vec::with_capacity(64);
    for (name, cluster) in [
        (*b".          ", self_cluster),
        (*b"..         ", parent_cluster),
    ] {
        let mut entry = [0u8; DIR_ENTRY_SIZE];
        entry[0..11].copy_from_slice(&name);
        entry[11] = 0x10;
        entry[16..18].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
        entry[18..20].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
        entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
        entry[24..26].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
        entry[26..28].copy_from_slice(&((cluster & 0xFFFF) as u16).to_le_bytes());
        raw.extend_from_slice(&entry);
    }
    raw
}

fn volume_label_entry() -> Vec<u8> {
    let mut entry = [0u8; DIR_ENTRY_SIZE];
    entry[0..11].copy_from_slice(b"EFI        ");
    entry[11] = 0x08;
    entry[16..18].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry[18..20].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry[24..26].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry.to_vec()
}

fn append_child_entries(
    raw: &mut Vec<u8>,
    name: &str,
    short: &[u8; 11],
    needs_lfn: bool,
    is_dir: bool,
    cluster: u32,
    size: u32,
) {
    if needs_lfn {
        for e in build_lfn_entries(name, short) {
            raw.extend_from_slice(&e);
        }
    }
    let mut entry = [0u8; DIR_ENTRY_SIZE];
    entry[0..11].copy_from_slice(short);
    entry[11] = if is_dir { 0x10 } else { 0x20 };
    entry[12] = 0;
    entry[13] = 0;
    entry[14..16].copy_from_slice(&0u16.to_le_bytes());
    entry[16..18].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry[18..20].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    entry[22..24].copy_from_slice(&0u16.to_le_bytes());
    entry[24..26].copy_from_slice(&FAT_EPOCH_DATE.to_le_bytes());
    entry[26..28].copy_from_slice(&((cluster & 0xFFFF) as u16).to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    raw.extend_from_slice(&entry);
}

fn validate_component_name_length(name: &str) -> Result<(), String> {
    if name.encode_utf16().count() > 255 {
        return Err(format!(
            "EFI file name component is too long for FAT: {name}"
        ));
    }
    Ok(())
}

struct Builder {
    layout: Layout,
    fat: Vec<u8>,
    data: Vec<u8>,
    next_cluster: u32,
    max_clusters: u32,
}

impl Builder {
    fn new(layout: Layout) -> Result<Self, String> {
        let max_clusters = layout.max_clusters();
        let max_clusters = u32::try_from(max_clusters)
            .map_err(|_| "EFI partition is too large for FAT cluster addressing".to_string())?;
        if max_clusters < 1 {
            return Err("EFI partition has no room for a data area".into());
        }
        let mut fat = vec![0u8; layout.fat_region_len()];
        fat_set(&mut fat, 0, 0x0FFF_FFF8, layout.fat_type);
        fat_set(&mut fat, 1, fat_eoc(layout.fat_type), layout.fat_type);
        let data = vec![0u8; layout.bytes_per_cluster() as usize * max_clusters as usize];
        Ok(Self {
            layout,
            fat,
            data,
            next_cluster: 2,
            max_clusters,
        })
    }

    fn cluster_bytes_mut(&mut self, cluster: u32) -> &mut [u8] {
        let cbytes = self.layout.bytes_per_cluster() as usize;
        let start = (u64::from(cluster) - 2) as usize * cbytes;
        &mut self.data[start..start + cbytes]
    }

    fn reserve_head(&mut self) -> Result<u32, String> {
        if self.next_cluster > self.max_clusters + 1 {
            return Err("EFI partition is out of space for its directory tree".into());
        }
        let c = self.next_cluster;
        self.next_cluster += 1;
        fat_set(
            &mut self.fat,
            c,
            fat_eoc(self.layout.fat_type),
            self.layout.fat_type,
        );
        Ok(c)
    }

    fn alloc_chain(&mut self, needed: u32) -> Result<u32, String> {
        if needed == 0
            || self
                .next_cluster
                .checked_add(needed - 1)
                .is_none_or(|last| last > self.max_clusters + 1)
        {
            return Err("EFI partition is out of space for its files".into());
        }
        let head = self.next_cluster;
        let mut prev: Option<u32> = None;
        for _ in 0..needed {
            let c = self.next_cluster;
            self.next_cluster += 1;
            if let Some(p) = prev {
                fat_set(&mut self.fat, p, c, self.layout.fat_type);
            }
            prev = Some(c);
        }
        fat_set(
            &mut self.fat,
            prev.unwrap(),
            fat_eoc(self.layout.fat_type),
            self.layout.fat_type,
        );
        Ok(head)
    }

    fn write_chain(&mut self, head: u32, bytes: &[u8]) {
        let cbytes = self.layout.bytes_per_cluster() as usize;
        let mut cluster = head;
        let mut offset = 0usize;
        loop {
            let take = (bytes.len() - offset).min(cbytes);
            let next = fat_get(&self.fat, cluster, self.layout.fat_type);
            let dst = self.cluster_bytes_mut(cluster);
            if take > 0 {
                dst[..take].copy_from_slice(&bytes[offset..offset + take]);
            }
            offset += take;
            if offset >= bytes.len() {
                break;
            }
            cluster = next;
        }
    }

    fn write_file(&mut self, bytes: &[u8]) -> Result<u32, String> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let cbytes = self.layout.bytes_per_cluster() as usize;
        let needed = u32::try_from(bytes.len().div_ceil(cbytes))
            .map_err(|_| "EFI file exceeds addressable FAT cluster range".to_string())?;
        let head = self.alloc_chain(needed)?;
        self.write_chain(head, bytes);
        Ok(head)
    }

    fn extend_and_write_dir(&mut self, head: u32, bytes: &[u8]) -> Result<(), String> {
        let cbytes = self.layout.bytes_per_cluster() as usize;
        let needed = bytes.len().max(1).div_ceil(cbytes).max(1);
        let extra = needed - 1;
        if extra > 0 {
            let extra = u32::try_from(extra)
                .map_err(|_| "EFI directory exceeds addressable FAT cluster range".to_string())?;
            if self
                .next_cluster
                .checked_add(extra - 1)
                .is_none_or(|last| last > self.max_clusters + 1)
            {
                return Err("EFI partition is out of space for its directory tree".into());
            }
            let first_extra = self.next_cluster;
            fat_set(&mut self.fat, head, first_extra, self.layout.fat_type);
            let mut prev = first_extra;
            self.next_cluster += 1;
            for _ in 1..extra {
                let c = self.next_cluster;
                self.next_cluster += 1;
                fat_set(&mut self.fat, prev, c, self.layout.fat_type);
                prev = c;
            }
            fat_set(
                &mut self.fat,
                prev,
                fat_eoc(self.layout.fat_type),
                self.layout.fat_type,
            );
        }
        self.write_chain(head, bytes);
        Ok(())
    }

    fn finish(
        self,
        layout: &Layout,
        root_cluster: Option<u32>,
        fat16_root_raw: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, String> {
        let total_bytes = layout.total_sectors as usize * layout.bytes_per_sector as usize;
        let mut image = vec![0u8; total_bytes];
        let used = self.next_cluster - 2;
        let free_clusters = self.max_clusters.saturating_sub(used);
        let next_free = if free_clusters == 0 {
            0xFFFF_FFFF
        } else {
            self.next_cluster
        };
        let volume_label = *b"EFI        ";
        write_bpb(&mut image, layout, root_cluster.unwrap_or(0), &volume_label);
        let bps = layout.bytes_per_sector as usize;
        if layout.fat_type == FatType::Fat32 {
            if image.len() >= 2 * bps {
                write_fsinfo(&mut image[bps..2 * bps], free_clusters, next_free);
            }
            if image.len() >= 8 * bps {
                let (primary, rest) = image.split_at_mut(6 * bps);
                rest[..2 * bps].copy_from_slice(&primary[..2 * bps]);
            }
        }
        let fat_region_start = layout.first_fat_sector() as usize * bps;
        let fat_bytes_len = self.fat.len();
        for i in 0..layout.num_fats as usize {
            let start = fat_region_start + i * fat_bytes_len;
            image[start..start + fat_bytes_len].copy_from_slice(&self.fat);
        }
        if let Some(raw) = fat16_root_raw {
            let root_start = layout.first_root_dir_sector() as usize * bps;
            image[root_start..root_start + raw.len()].copy_from_slice(&raw);
        }
        let data_start = layout.first_data_sector() as usize * bps;
        image[data_start..data_start + self.data.len()].copy_from_slice(&self.data);
        Ok(image)
    }
}

fn encode_dir(
    builder: &mut Builder,
    path: &Path,
    self_cluster: u32,
    parent_cluster_for_dotdot: u32,
    is_root: bool,
) -> Result<Vec<u8>, String> {
    let mut children: Vec<(String, PathBuf, bool)> = fs::read_dir(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .map(|entry| {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "EFI file name is not valid UTF-8".to_string())?;
            let is_dir = entry.file_type().map_err(|e| e.to_string())?.is_dir();
            Ok((name, entry.path(), is_dir))
        })
        .collect::<Result<Vec<_>, String>>()?;
    children.sort_by(|a, b| a.0.cmp(&b.0));

    let mut raw = if is_root {
        volume_label_entry()
    } else {
        dot_entries(self_cluster, parent_cluster_for_dotdot)
    };
    let mut used_short: HashSet<[u8; 11]> = HashSet::new();
    if is_root {
        used_short.insert(*b"EFI        ");
    } else {
        used_short.insert(*b".          ");
        used_short.insert(*b"..         ");
    }
    for (name, child_path, is_dir) in children {
        validate_component_name_length(&name)?;
        let (short, needs_lfn) = build_short_and_lfn(&name, &mut used_short)?;
        if is_dir {
            let child_cluster = builder.reserve_head()?;
            let dotdot = if is_root { 0 } else { self_cluster };
            let child_raw = encode_dir(builder, &child_path, child_cluster, dotdot, false)?;
            builder.extend_and_write_dir(child_cluster, &child_raw)?;
            append_child_entries(&mut raw, &name, &short, needs_lfn, true, child_cluster, 0);
        } else {
            let bytes =
                fs::read(&child_path).map_err(|e| format!("{}: {e}", child_path.display()))?;
            let size = u32::try_from(bytes.len()).map_err(|_| {
                format!(
                    "{} exceeds the 4 GiB FAT file size limit",
                    child_path.display()
                )
            })?;
            let cluster = builder.write_file(&bytes)?;
            append_child_entries(&mut raw, &name, &short, needs_lfn, false, cluster, size);
        }
    }
    Ok(raw)
}

fn encode_fat32(layout: &Layout, staged: &Path) -> Result<Vec<u8>, String> {
    let root_cluster = 2u32;
    let mut builder = Builder::new(*layout)?;
    if builder.max_clusters < 1 {
        return Err("EFI partition has no room for a FAT32 root directory".into());
    }
    builder.next_cluster = 3;
    fat_set(
        &mut builder.fat,
        2,
        fat_eoc(layout.fat_type),
        layout.fat_type,
    );
    let raw_root = encode_dir(&mut builder, staged, root_cluster, 0, true)?;
    builder.extend_and_write_dir(root_cluster, &raw_root)?;
    builder.finish(layout, Some(root_cluster), None)
}

fn encode_fat16(layout: &Layout, staged: &Path) -> Result<Vec<u8>, String> {
    let mut builder = Builder::new(*layout)?;
    let raw_root = encode_dir(&mut builder, staged, 0, 0, true)?;
    let root_area_bytes = layout.root_dir_sectors() as usize * layout.bytes_per_sector as usize;
    if raw_root.len() > root_area_bytes {
        return Err("Too many files for the legacy FAT16 root directory".into());
    }
    builder.finish(layout, None, Some(raw_root))
}

fn format_image(
    fat_type: FatType,
    total_sectors: u64,
    bytes_per_sector: u32,
    hidden_sectors: u32,
    staged: &Path,
) -> Result<Vec<u8>, String> {
    let (spc, reserved, num_fats, root_entry_count) = match fat_type {
        FatType::Fat32 => (
            choose_spc_fat32(total_sectors, bytes_per_sector),
            32u32,
            2u32,
            0u32,
        ),
        FatType::Fat16 => (1u32, 1u32, 2u32, 512u32),
    };
    let mut layout = Layout {
        fat_type,
        bytes_per_sector,
        sectors_per_cluster: spc,
        reserved_sectors: reserved,
        num_fats,
        root_entry_count,
        total_sectors,
        hidden_sectors,
        fat_size_sectors: 0,
    };
    layout.fat_size_sectors = compute_fat_size(&layout)?;
    match fat_type {
        FatType::Fat32 => encode_fat32(&layout, staged),
        FatType::Fat16 => encode_fat16(&layout, staged),
    }
}

fn parse_layout(container: &[u8]) -> Result<(Layout, u32), String> {
    let sector_size = efi_sector_size(container)?;
    if container.len() < 90 {
        return Err("EFI filesystem BPB is truncated".into());
    }
    let le16 = |o: usize| u16::from_le_bytes(container[o..o + 2].try_into().unwrap());
    let le32 = |o: usize| u32::from_le_bytes(container[o..o + 4].try_into().unwrap());
    let spc = u32::from(container[13]);
    if spc == 0 {
        return Err("EFI filesystem has an invalid sectors-per-cluster value".into());
    }
    let reserved = u32::from(le16(14));
    if reserved == 0 {
        return Err("EFI filesystem has zero reserved sectors".into());
    }
    let num_fats = u32::from(container[16]);
    if num_fats == 0 {
        return Err("EFI filesystem reports zero FAT copies".into());
    }
    let root_entry_count = u32::from(le16(17));
    let tot16 = u64::from(le16(19));
    let fat16_sz = u32::from(le16(22));
    let hidden = le32(28);
    let tot32 = u64::from(le32(32));
    let total_sectors = if tot32 != 0 { tot32 } else { tot16 };
    if total_sectors == 0 {
        return Err("EFI filesystem reports zero total sectors".into());
    }
    let (fat_type, fat_size, root_cluster) = if fat16_sz != 0 {
        (FatType::Fat16, fat16_sz, 0u32)
    } else {
        let fat32_sz = le32(36);
        if fat32_sz == 0 {
            return Err("EFI filesystem BPB has no FAT size in either field".into());
        }
        let rc = le32(44);
        if rc < 2 {
            return Err("EFI filesystem has an invalid FAT32 root cluster".into());
        }
        (FatType::Fat32, fat32_sz, rc)
    };
    if fat_type == FatType::Fat32 && root_entry_count != 0 {
        return Err("EFI FAT32 filesystem must have a zero root entry count".into());
    }
    let layout = Layout {
        fat_type,
        bytes_per_sector: sector_size,
        sectors_per_cluster: spc,
        reserved_sectors: reserved,
        num_fats,
        root_entry_count,
        total_sectors,
        hidden_sectors: hidden,
        fat_size_sectors: fat_size,
    };
    let expected_len = total_sectors
        .checked_mul(u64::from(sector_size))
        .ok_or_else(|| "EFI filesystem size overflows".to_string())?;
    if expected_len != container.len() as u64 {
        return Err("EFI filesystem BPB total sectors does not match the image length".into());
    }
    Ok((layout, root_cluster))
}

#[derive(Clone, Debug)]
struct DirEntry {
    name: String,
    is_dir: bool,
    cluster: u32,
    size: u32,
}

fn decode_short_name(short: &[u8; 11]) -> String {
    let base = std::str::from_utf8(&short[0..8]).unwrap_or("").trim_end();
    let ext = std::str::from_utf8(&short[8..11]).unwrap_or("").trim_end();
    if ext.is_empty() {
        base.to_string()
    } else {
        format!("{base}.{ext}")
    }
}

fn parse_dir_region(region: &[u8]) -> Result<Vec<DirEntry>, String> {
    let mut entries = Vec::new();
    let mut lfn_parts: Vec<(u8, u8, [u16; LFN_CHARS_PER_ENTRY])> = Vec::new();
    let mut i = 0usize;
    while i + DIR_ENTRY_SIZE <= region.len() {
        let raw = &region[i..i + DIR_ENTRY_SIZE];
        i += DIR_ENTRY_SIZE;
        if raw[0] == 0x00 {
            break;
        }
        if raw[0] == 0xE5 {
            lfn_parts.clear();
            continue;
        }
        let attr = raw[11];
        if attr == 0x0F {
            let seq = raw[0] & !0x40;
            let checksum = raw[13];
            let mut chars = [0u16; LFN_CHARS_PER_ENTRY];
            for j in 0..5 {
                chars[j] = u16::from_le_bytes([raw[1 + j * 2], raw[2 + j * 2]]);
            }
            for j in 0..6 {
                chars[5 + j] = u16::from_le_bytes([raw[14 + j * 2], raw[15 + j * 2]]);
            }
            for j in 0..2 {
                chars[11 + j] = u16::from_le_bytes([raw[28 + j * 2], raw[29 + j * 2]]);
            }
            lfn_parts.push((seq, checksum, chars));
            continue;
        }
        if attr & 0x08 != 0 && attr & 0x10 == 0 {
            lfn_parts.clear();
            continue;
        }
        let short: [u8; 11] = raw[0..11].try_into().unwrap();
        let expected_checksum = lfn_checksum(&short);
        let name = if !lfn_parts.is_empty()
            && lfn_parts
                .iter()
                .all(|(_, chk, _)| *chk == expected_checksum)
        {
            let mut sorted = lfn_parts.clone();
            sorted.sort_by_key(|(seq, _, _)| *seq);
            let mut units = Vec::new();
            for (_, _, chars) in &sorted {
                for &u in chars {
                    if u == 0x0000 {
                        break;
                    }
                    units.push(u);
                }
            }
            String::from_utf16_lossy(&units)
        } else {
            decode_short_name(&short)
        };
        lfn_parts.clear();
        if name == "." || name == ".." {
            continue;
        }
        let is_dir = attr & 0x10 != 0;
        let cluster = (u32::from(u16::from_le_bytes([raw[20], raw[21]])) << 16)
            | u32::from(u16::from_le_bytes([raw[26], raw[27]]));
        let size = u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]);
        entries.push(DirEntry {
            name,
            is_dir,
            cluster,
            size,
        });
    }
    Ok(entries)
}

struct Reader<'a> {
    image: &'a [u8],
    layout: Layout,
    root_cluster: u32,
}

impl<'a> Reader<'a> {
    fn fat_slice(&self) -> &'a [u8] {
        let start = self.layout.first_fat_sector() as usize * self.layout.bytes_per_sector as usize;
        &self.image[start..start + self.layout.fat_region_len()]
    }

    fn cluster_chain_bytes(&self, cluster: u32, size_hint: Option<u32>) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        if cluster == 0 {
            return Ok(out);
        }
        let cbytes = self.layout.bytes_per_cluster() as usize;
        let mut visited = HashSet::new();
        let mut cluster = cluster;
        let fat = self.fat_slice();
        loop {
            if cluster < 2 || fat_is_eoc(self.layout.fat_type, cluster) {
                break;
            }
            if !visited.insert(cluster) {
                return Err("FAT cluster chain contains a loop".into());
            }
            if u64::from(cluster) > self.layout.max_clusters() + 1 {
                return Err("FAT cluster chain references an out-of-range cluster".into());
            }
            let off = self.layout.cluster_offset(cluster) as usize;
            if off + cbytes > self.image.len() {
                return Err("FAT cluster chain references data outside the image".into());
            }
            out.extend_from_slice(&self.image[off..off + cbytes]);
            if let Some(sz) = size_hint
                && out.len() as u64 >= u64::from(sz)
            {
                break;
            }
            cluster = fat_get(fat, cluster, self.layout.fat_type);
        }
        if let Some(sz) = size_hint {
            out.truncate(sz as usize);
        }
        Ok(out)
    }

    fn root_region_bytes(&self) -> Result<Vec<u8>, String> {
        if self.layout.fat_type == FatType::Fat16 {
            let start = self.layout.first_root_dir_sector() as usize
                * self.layout.bytes_per_sector as usize;
            let len =
                self.layout.root_dir_sectors() as usize * self.layout.bytes_per_sector as usize;
            if start + len > self.image.len() {
                return Err("Legacy FAT16 root directory extends past the image".into());
            }
            Ok(self.image[start..start + len].to_vec())
        } else {
            self.cluster_chain_bytes(self.root_cluster, None)
        }
    }

    fn dir_region_bytes(&self, cluster: u32) -> Result<Vec<u8>, String> {
        self.cluster_chain_bytes(cluster, None)
    }
}

fn lookup_path(reader: &Reader, path: &str) -> Result<(bool, u32, u32), String> {
    let components: Vec<&str> = path.split('/').collect();
    let mut current_entries = parse_dir_region(&reader.root_region_bytes()?)?;
    let mut result: Option<(bool, u32, u32)> = None;
    for (idx, comp) in components.iter().enumerate() {
        let found = current_entries
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(comp))
            .ok_or_else(|| format!("EFI file not found: {path}"))?;
        let last = idx + 1 == components.len();
        if last {
            result = Some((found.is_dir, found.cluster, found.size));
        } else {
            if !found.is_dir {
                return Err(format!("EFI path component is not a directory: {path}"));
            }
            current_entries = parse_dir_region(&reader.dir_region_bytes(found.cluster)?)?;
        }
    }
    result.ok_or_else(|| format!("EFI file not found: {path}"))
}

fn extract_dir(
    reader: &Reader,
    entries: &[DirEntry],
    out: &Path,
    depth: u32,
) -> Result<(), String> {
    if depth > 64 {
        return Err("EFI directory tree is too deep".into());
    }
    for e in entries {
        if e.name.is_empty() || e.name.contains('/') || e.name.contains('\\') {
            return Err(format!(
                "EFI directory entry has an unsafe name: {}",
                e.name
            ));
        }
        let target = out.join(&e.name);
        if e.is_dir {
            fs::create_dir(&target).map_err(|err| format!("{}: {err}", target.display()))?;
            let sub_entries = parse_dir_region(&reader.dir_region_bytes(e.cluster)?)?;
            extract_dir(reader, &sub_entries, &target, depth + 1)?;
        } else {
            let bytes = reader.cluster_chain_bytes(e.cluster, Some(e.size))?;
            fs::write(&target, &bytes).map_err(|err| format!("{}: {err}", target.display()))?;
        }
    }
    Ok(())
}

fn extract_to_dir(
    container: &[u8],
    layout: &Layout,
    root_cluster: u32,
    out: &Path,
) -> Result<(), String> {
    let reader = Reader {
        image: container,
        layout: *layout,
        root_cluster,
    };
    let root_entries = parse_dir_region(&reader.root_region_bytes()?)?;
    extract_dir(&reader, &root_entries, out, 0)
}

fn self_check(image: &[u8]) -> Result<(), String> {
    let (layout, root_cluster) = parse_layout(image)?;
    let reader = Reader {
        image,
        layout,
        root_cluster,
    };
    let root_entries = parse_dir_region(&reader.root_region_bytes()?)?;
    fn walk(reader: &Reader, entries: &[DirEntry], depth: u32) -> Result<(), String> {
        if depth > 64 {
            return Err("EFI directory tree is too deep".into());
        }
        for e in entries {
            if e.is_dir {
                if e.cluster < 2 {
                    return Err(format!("EFI directory '{}' has an invalid cluster", e.name));
                }
                let sub = parse_dir_region(&reader.dir_region_bytes(e.cluster)?)?;
                walk(reader, &sub, depth + 1)?;
            } else {
                let bytes = reader.cluster_chain_bytes(e.cluster, Some(e.size))?;
                if bytes.len() != e.size as usize {
                    return Err(format!("EFI file '{}' is truncated", e.name));
                }
            }
        }
        Ok(())
    }
    walk(&reader, &root_entries, 0)
}

pub fn create_efi(
    part_bytes: u64,
    sector_size: u32,
    partition_start_lba: u32,
    files: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    validate_efi_files(files)?;
    validate_efi_geometry(part_bytes, sector_size)?;
    let total_sectors = part_bytes / u64::from(sector_size);
    let staged = tempfile::tempdir().map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        write(staged.path(), name, bytes)?;
    }
    let image = format_image(
        FatType::Fat32,
        total_sectors,
        sector_size,
        partition_start_lba,
        staged.path(),
    )?;
    self_check(&image)?;
    Ok(image)
}

pub fn update_efi(container: &[u8], files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    validate_efi_files(files)?;
    let (layout, root_cluster) = parse_layout(container)?;
    let staged = tempfile::tempdir().map_err(|e| e.to_string())?;
    extract_to_dir(container, &layout, root_cluster, staged.path())?;
    for (name, bytes) in files {
        write(staged.path(), name, bytes)?;
    }
    let image = match layout.fat_type {
        FatType::Fat32 => encode_fat32(&layout, staged.path())?,
        FatType::Fat16 => encode_fat16(&layout, staged.path())?,
    };
    if image.len() != container.len() {
        return Err("EFI filesystem update changed the image length".into());
    }
    self_check(&image)?;
    Ok(image)
}

pub fn read_efi_file(container: &[u8], path: &str) -> Result<Vec<u8>, String> {
    let mut files = read_efi_files(container, &[path])?;
    Ok(files.remove(0))
}

pub fn read_efi_files(container: &[u8], paths: &[&str]) -> Result<Vec<Vec<u8>>, String> {
    validate_efi_files(
        &paths
            .iter()
            .map(|p| ((*p).to_owned(), Vec::new()))
            .collect::<Vec<_>>(),
    )?;
    let (layout, root_cluster) = parse_layout(container)?;
    let reader = Reader {
        image: container,
        layout,
        root_cluster,
    };
    paths
        .iter()
        .map(|path| {
            let (is_dir, cluster, size) = lookup_path(&reader, path)?;
            if is_dir {
                return Err(format!("EFI path is a directory: {path}"));
            }
            reader.cluster_chain_bytes(cluster, Some(size))
        })
        .collect()
}

#[cfg(test)]
fn format_fat16_for_test(
    part_bytes: u64,
    sector_size: u32,
    files: &[(String, Vec<u8>)],
) -> Result<Vec<u8>, String> {
    validate_efi_files(files)?;
    validate_efi_geometry(part_bytes, sector_size)?;
    let total_sectors = part_bytes / u64::from(sector_size);
    let staged = tempfile::tempdir().map_err(|e| e.to_string())?;
    for (name, bytes) in files {
        write(staged.path(), name, bytes)?;
    }
    let image = format_image(FatType::Fat16, total_sectors, sector_size, 0, staged.path())?;
    self_check(&image)?;
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_path_traversal() {
        let root = tempfile::tempdir().unwrap();
        assert!(write(root.path(), "../boot.bin", b"boot").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_parents_and_targets() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("boot.bin");
        fs::write(&target, b"original").unwrap();
        symlink(outside.path(), root.path().join("group")).unwrap();
        assert!(write(root.path(), "group/boot.bin", b"replacement").is_err());
        symlink(&target, root.path().join("boot.bin")).unwrap();
        assert!(write(root.path(), "boot.bin", b"replacement").is_err());
        assert_eq!(fs::read(target).unwrap(), b"original");
    }

    #[test]
    fn rejects_invalid_fat_geometry() {
        for sector in [0, 256, 768, 8192] {
            assert!(validate_efi_geometry(64 * 1024 * 1024, sector).is_err());
        }
        assert!(validate_efi_geometry(4097, 4096).is_err());
        assert!(validate_efi_geometry(0, 4096).is_err());
    }

    #[test]
    fn rejects_ambiguous_and_unsafe_fat_names() {
        for name in [
            "../boot.bin",
            "/boot.bin",
            "EFI//boot.bin",
            "EFI/boot.bin.",
            "EFI/boot:bin",
            "EFI\\boot.bin",
        ] {
            assert!(
                validate_efi_files(&[(name.into(), vec![])]).is_err(),
                "{name}"
            );
        }
        assert!(
            validate_efi_files(&[
                ("EFI/BOOT/file".into(), vec![]),
                ("efi/boot/FILE".into(), vec![])
            ])
            .is_err()
        );
        assert!(
            validate_efi_files(&[
                ("EFI/BOOT/BOOTAA64.EFI".into(), vec![]),
                ("vendor/long directory name/boot file.bin".into(), vec![])
            ])
            .is_ok()
        );
    }

    #[test]
    fn native_fat_create_read_and_update_preserve_sector_geometry() {
        for sector in [512, 4096] {
            let first = vec![0xa5; 25000];
            let unchanged = vec![0x5a; 7000];
            let files = vec![
                ("m1n1/boot.bin".into(), first.clone()),
                ("EFI/BOOT/BOOTAA64.EFI".into(), unchanged.clone()),
            ];
            let image = create_efi(512 * 1024 * 1024, sector, 655616, &files).unwrap();
            let le16 =
                |offset| u16::from_le_bytes(image[offset..offset + 2].try_into().unwrap()) as u64;
            let le32 =
                |offset| u32::from_le_bytes(image[offset..offset + 4].try_into().unwrap()) as u64;
            assert_eq!(
                le32(28),
                655616,
                "hidden sectors must reflect the partition offset"
            );
            assert_eq!(le16(17), 0, "FAT32 has no fixed root directory");
            assert_eq!(le16(22), 0, "FAT32 uses its extended sectors-per-FAT field");
            let data_sectors = le32(32) - le16(14) - u64::from(image[16]) * le32(36);
            assert!(
                data_sectors / u64::from(image[13]) >= 65525,
                "cluster count must identify FAT32"
            );
            assert!(
                le32(44) >= 2,
                "FAT32 root directory has an allocated cluster"
            );
            assert_eq!(efi_sector_size(&image).unwrap(), sector);
            assert_eq!(read_efi_file(&image, "m1n1/boot.bin").unwrap(), first);
            let replacement = vec![0x17; 90000];
            let updated =
                update_efi(&image, &[("m1n1/boot.bin".into(), replacement.clone())]).unwrap();
            assert_eq!(efi_sector_size(&updated).unwrap(), sector);
            assert_eq!(
                read_efi_files(&updated, &["m1n1/boot.bin", "EFI/BOOT/BOOTAA64.EFI"]).unwrap(),
                vec![replacement, unchanged]
            );
        }
    }

    #[test]
    fn native_legacy_fat16_update_preserves_geometry() {
        let bytes = format_fat16_for_test(
            64 * 1024 * 1024,
            512,
            &[("m1n1/boot.bin".into(), b"original".to_vec())],
        )
        .unwrap();
        let updated =
            update_efi(&bytes, &[("m1n1/boot.bin".into(), b"replacement".to_vec())]).unwrap();
        assert_eq!(efi_sector_size(&updated).unwrap(), 512);
        assert_ne!(u16::from_le_bytes(updated[22..24].try_into().unwrap()), 0);
        assert_eq!(
            read_efi_file(&updated, "m1n1/boot.bin").unwrap(),
            b"replacement"
        );
    }

    #[test]
    fn round_trips_nested_directories_and_long_names() {
        let files = vec![
            ("EFI/BOOT/BOOTAA64.EFI".into(), vec![0x11u8; 4096]),
            (
                "vendor/long directory name/boot file.bin".into(),
                vec![0x22u8; 12345],
            ),
            ("m1n1/boot.bin".into(), vec![0x33u8; 1]),
            ("empty.txt".into(), vec![]),
        ];
        let image = create_efi(64 * 1024 * 1024, 512, 2048, &files).unwrap();
        for (name, bytes) in &files {
            assert_eq!(&read_efi_file(&image, name).unwrap(), bytes, "{name}");
        }
        let all = read_efi_files(
            &image,
            &[
                "EFI/BOOT/BOOTAA64.EFI",
                "vendor/long directory name/boot file.bin",
                "m1n1/boot.bin",
                "empty.txt",
            ],
        )
        .unwrap();
        assert_eq!(all[0], files[0].1);
        assert_eq!(all[1], files[1].1);
    }

    #[test]
    fn update_can_add_new_files_without_disturbing_others() {
        let files = vec![("a/b.bin".into(), vec![1u8, 2, 3])];
        let image = create_efi(32 * 1024 * 1024, 512, 128, &files).unwrap();
        let updated = update_efi(&image, &[("a/c/new.bin".into(), vec![9u8, 9, 9, 9])]).unwrap();
        assert_eq!(updated.len(), image.len());
        assert_eq!(read_efi_file(&updated, "a/b.bin").unwrap(), vec![1, 2, 3]);
        assert_eq!(
            read_efi_file(&updated, "a/c/new.bin").unwrap(),
            vec![9, 9, 9, 9]
        );
    }

    #[test]
    fn create_efi_rejects_traversal_and_symlink_style_paths() {
        assert!(create_efi(32 * 1024 * 1024, 512, 0, &[("../x".into(), vec![])]).is_err());
    }
}
