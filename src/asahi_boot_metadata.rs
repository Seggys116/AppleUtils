use std::io::{Read, Seek, SeekFrom, Write};

pub(crate) fn normalize_ext4_environment<R: Read + Write + Seek>(
    source: &mut R,
) -> Result<bool, String> {
    let file = {
        let Some(mut image) = crate::ext4_boot::Ext4::open(&mut *source)? else {
            return Ok(false);
        };
        image.file("/grub2/grubenv")?
    };
    let Some(file) = file else {
        return Ok(false);
    };
    let Some(replacement) = environment_without_raw_redirect(&file.bytes)? else {
        return Ok(false);
    };
    let text = std::str::from_utf8(&file.bytes).map_err(|_| "invalid GRUB environment encoding")?;
    let target = text
        .lines()
        .find_map(|line| line.strip_prefix("env_block="))
        .ok_or("missing GRUB redirect")?;
    let image_len = source.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    let mut valid_range = true;
    for extent in target.split(',') {
        let (start, count) = extent.split_once('+').ok_or("invalid GRUB blocklist")?;
        let offset = start
            .parse::<u64>()
            .map_err(|e| e.to_string())?
            .checked_mul(512)
            .ok_or("GRUB blocklist overflow")?;
        let size = count
            .parse::<u64>()
            .map_err(|e| e.to_string())?
            .checked_mul(512)
            .ok_or("GRUB blocklist overflow")?;
        if size > 1024 * 1024
            || raw.len() as u64 + size > 1024 * 1024
            || offset.checked_add(size).is_none_or(|end| end > image_len)
        {
            valid_range = false;
            break;
        }
        source
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        let at = raw.len();
        raw.resize(at + size as usize, 0);
        source
            .read_exact(&mut raw[at..])
            .map_err(|e| e.to_string())?;
    }
    if valid_range && validate_environment(&raw).is_ok() {
        return Ok(false);
    }

    let mut at = 0;
    for (offset, count) in file.ranges {
        source
            .seek(SeekFrom::Start(offset))
            .map_err(|e| e.to_string())?;
        source
            .write_all(&replacement[at..at + count])
            .map_err(|e| e.to_string())?;
        at += count;
    }
    Ok(true)
}

fn validate_environment(bytes: &[u8]) -> Result<&str, String> {
    if bytes.len() < 512
        || !bytes.len().is_multiple_of(512)
        || !bytes.starts_with(b"# GRUB Environment Block\n")
    {
        return Err("invalid GRUB environment block size or header".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "GRUB environment is not UTF-8")?;
    let mut keys = std::collections::BTreeSet::new();
    for line in text.split_inclusive('\n') {
        if line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_suffix('\n')
            .ok_or("unterminated GRUB environment entry")?;
        let (key, _) = line
            .split_once('=')
            .ok_or("invalid GRUB environment entry")?;
        if key.is_empty()
            || key.bytes().any(|b| b.is_ascii_control() || b == b' ')
            || !keys.insert(key)
        {
            return Err("invalid or duplicate GRUB environment variable".into());
        }
    }
    Ok(text)
}

fn environment_without_raw_redirect(bytes: &[u8]) -> Result<Option<Vec<u8>>, String> {
    let text = validate_environment(bytes)?;
    let mut result = Vec::with_capacity(bytes.len());
    let mut changed = false;
    for line in text.split_inclusive('\n') {
        if let Some(value) = line.strip_prefix("env_block=") {
            let value = value.trim_end_matches('\n');
            if value.starts_with('(') || value.contains('/') {
                return Ok(None);
            }
            if value.is_empty()
                || !value.split(',').all(|extent| {
                    let Some((start, len)) = extent.split_once('+') else {
                        return false;
                    };
                    start.parse::<u64>().is_ok() && len.parse::<u64>().is_ok_and(|n| n > 0)
                })
            {
                return Err("ext4 grubenv contains an invalid raw blocklist".into());
            }
            changed = true;
        } else {
            result.extend_from_slice(line.as_bytes());
        }
    }
    if !changed {
        return Ok(None);
    }
    result.resize(bytes.len(), b'#');
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(target: &str) -> Vec<u8> {
        let mut image = vec![0; 16384];
        fn u16w(b: &mut [u8], at: usize, value: u16) {
            b[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn u32w(b: &mut [u8], at: usize, value: u32) {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        u32w(&mut image, 1024, 8);
        u32w(&mut image, 1028, 16);
        u32w(&mut image, 1056, 16);
        u32w(&mut image, 1044, 1);
        u32w(&mut image, 1064, 8);
        u16w(&mut image, 1080, 0xef53);
        u32w(&mut image, 2056, 3);
        for (number, mode, block) in [(2, 0x4000, 4), (3, 0x8000, 5)] {
            let at = 3072 + (number - 1) * 128;
            u16w(&mut image, at, mode);
            u32w(&mut image, at + 4, 1024);
            u32w(&mut image, at + 32, 0x80000);
            u16w(&mut image, at + 40, 0xf30a);
            u16w(&mut image, at + 42, 1);
            u16w(&mut image, at + 44, 4);
            u16w(&mut image, at + 56, 1);
            u32w(&mut image, at + 60, block);
        }
        u32w(&mut image, 4096, 2);
        u16w(&mut image, 4100, 16);
        image[4102] = 5;
        image[4104..4109].copy_from_slice(b"grub2");
        u32w(&mut image, 4112, 3);
        u16w(&mut image, 4116, 1008);
        image[4118] = 7;
        image[4120..4127].copy_from_slice(b"grubenv");
        let env = format!("# GRUB Environment Block\nenv_block={target}\nsaved_entry=test\n");
        image[5120..6144].fill(b'#');
        image[5120..5120 + env.len()].copy_from_slice(env.as_bytes());
        image
    }
    #[test]
    fn journal_recovery_and_metadata_overlap_prevent_writes() {
        for (offset, value) in [(1120, 4u32), (3388, 3u32)] {
            let mut original = fixture("512+1");
            original[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            let mut source = std::io::Cursor::new(original.clone());
            assert!(normalize_ext4_environment(&mut source).is_err());
            assert_eq!(source.into_inner(), original);
        }
    }
    #[test]
    fn external_environment_is_preserved() {
        let original = fixture("(hd1)/grubenv");
        let mut source = std::io::Cursor::new(original.clone());
        assert!(!normalize_ext4_environment(&mut source).unwrap());
        assert_eq!(source.into_inner(), original);
    }
    #[test]
    fn duplicate_redirects_and_truncated_environments_are_rejected() {
        let mut data = b"# GRUB Environment Block\nenv_block=1+1\nenv_block=2+1\n".to_vec();
        data.resize(1024, b'#');
        assert!(environment_without_raw_redirect(&data).is_err());
        assert!(validate_environment(b"# GRUB Environment Block\n").is_err());
    }
    #[test]
    fn ext4_rebinds_invalid_raw_target_without_metadata_changes() {
        let original = fixture("512+1");
        let mut source = std::io::Cursor::new(original.clone());
        assert!(normalize_ext4_environment(&mut source).unwrap());
        let output = source.into_inner();
        assert_eq!(&original[..5120], &output[..5120]);
        assert_eq!(&original[6144..], &output[6144..]);
        assert!(
            std::str::from_utf8(&output[5120..6144])
                .unwrap()
                .contains("saved_entry=test\n")
        );
        assert!(!normalize_ext4_environment(&mut std::io::Cursor::new(output)).unwrap());
    }
    #[test]
    fn ext4_preserves_valid_raw_environment() {
        let original = fixture("10+2");
        let mut source = std::io::Cursor::new(original.clone());
        assert!(!normalize_ext4_environment(&mut source).unwrap());
        assert_eq!(source.into_inner(), original);
    }
    #[test]
    fn invalid_extent_is_rejected_before_writes() {
        let mut original = fixture("512+1");
        original[3388..3392].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut source = std::io::Cursor::new(original.clone());
        assert!(normalize_ext4_environment(&mut source).is_err());
        assert_eq!(source.into_inner(), original);
    }
    #[test]
    fn preserves_persistent_environment_values_and_size() {
        let mut input = b"# GRUB Environment Block\nenv_block=512+1\nsaved_entry=test\nnext_entry=next\nboot_success=0\n".to_vec();
        input.resize(1024, b'#');
        let output = environment_without_raw_redirect(&input).unwrap().unwrap();
        assert_eq!(output.len(), 1024);
        let text = std::str::from_utf8(&output).unwrap();
        assert!(!text.contains("env_block="));
        assert!(text.contains("saved_entry=test\nnext_entry=next\nboot_success=0\n"));
        assert!(environment_without_raw_redirect(&output).unwrap().is_none());
    }
    #[test]
    fn does_not_guess_external_or_malformed_targets() {
        for value in ["abc", "1+0"] {
            let mut input = format!("# GRUB Environment Block\nenv_block={value}\n");
            input.extend(std::iter::repeat_n('#', 1024 - input.len()));
            assert!(environment_without_raw_redirect(input.as_bytes()).is_err());
        }
    }
}
