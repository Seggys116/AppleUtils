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

const SILENCE_KEYS: &[&str] = &["quiet", "rhgb", "splash"];
/// The upstream Apple device trees alias each board's debug UART as serial0 and select it
/// with stdout-path, and samsung_tty numbers apple,s5l-uart ports by that alias, so the
/// board's serial console is ttySAC0. No rate is given, so the driver keeps the one the
/// boot firmware programmed. tty0 keeps kernel output on the display; the serial port is
/// last so it becomes /dev/console and receives the login getty.
const SERIAL_CONSOLE: &[&str] = &["console=tty0", "console=ttySAC0"];
const CMDLINE_FILES: &[&str] = &[
    "/etc/kernel/cmdline",
    "/etc/default/grub",
    "/grub2/grub.cfg",
    "/grub/grub.cfg",
    "/boot/grub2/grub.cfg",
    "/boot/grub/grub.cfg",
];
const ENTRY_DIRS: &[&str] = &["/loader/entries", "/boot/loader/entries"];
/// Bytes to write over the physical ranges they occupy, in order.
type Replacement = (Vec<(u64, usize)>, Vec<u8>);

pub(crate) fn enable_verbose_kernel<R: Read + Write + Seek>(
    source: &mut R,
) -> Result<bool, String> {
    let replacements = {
        let Some(mut image) = crate::ext4_boot::Ext4::open(&mut *source)? else {
            return Ok(false);
        };
        verbose_replacements(&mut image)?
    };
    if replacements.is_empty() {
        return Ok(false);
    }
    for (ranges, bytes) in replacements {
        let mut at = 0;
        for (offset, count) in ranges {
            source
                .seek(SeekFrom::Start(offset))
                .map_err(|e| e.to_string())?;
            source
                .write_all(&bytes[at..at + count])
                .map_err(|e| e.to_string())?;
            at += count;
        }
    }
    Ok(true)
}

fn verbose_replacements(
    image: &mut crate::ext4_boot::Ext4<impl Read + Seek>,
) -> Result<Vec<Replacement>, String> {
    let mut paths: Vec<String> = CMDLINE_FILES
        .iter()
        .map(|path| (*path).to_string())
        .collect();
    for dir in ENTRY_DIRS {
        if let Some(names) = image.files_in(dir)? {
            for name in names {
                if name.ends_with(".conf") {
                    paths.push(format!("{dir}/{name}"));
                }
            }
        }
    }
    let mut replacements = Vec::new();
    for path in paths {
        let Some(file) = image.file(&path)? else {
            continue;
        };
        let mut refusal = None;
        let mut chosen = None;
        for mut output in verbose_candidates(&file.bytes)? {
            if output.len() <= file.bytes.len() {
                output.resize(file.bytes.len(), b' ');
                chosen = Some(vec![(file.ranges.clone(), output)]);
                break;
            }
            match image.resize_in_place(&path, output.len() as u64) {
                Ok(Some(resize)) => {
                    chosen = Some(vec![
                        (resize.ranges, output),
                        (
                            vec![(resize.inode_offset, resize.inode.len())],
                            resize.inode,
                        ),
                    ]);
                    break;
                }
                Ok(None) => return Err(format!("{path} is not a regular file")),
                Err(e) => refusal = Some(e),
            }
        }
        match (chosen, refusal) {
            (Some(writes), _) => replacements.extend(writes),
            (None, Some(e)) => {
                return Err(format!(
                    "verbose kernel command line does not fit in the existing boot file: {e}"
                ));
            }
            (None, None) => {}
        }
    }
    Ok(replacements)
}

/// Verbose rewrites of a boot file in order of preference: with loglevel=7, then without it
/// for a file whose allocated blocks cannot take the longer line.
fn verbose_candidates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "boot console file is not UTF-8")?;
    Ok([true, false]
        .into_iter()
        .filter_map(|add_loglevel| rewrite_boot_text(text, add_loglevel))
        .map(String::into_bytes)
        .collect())
}

fn rewrite_boot_text(text: &str, add_loglevel: bool) -> Option<String> {
    // grub-mkconfig puts GRUB_CMDLINE_LINUX on every entry and appends
    // GRUB_CMDLINE_LINUX_DEFAULT to the normal ones, so the console goes on the former
    // alone and on the latter only when the file does not set the former.
    let default_takes_console = !text
        .lines()
        .any(|line| line.trim_start().starts_with("GRUB_CMDLINE_LINUX="));
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(body) => (body, "\n"),
            None => (line, ""),
        };
        let cr = body.ends_with('\r');
        let body = body.strip_suffix('\r').unwrap_or(body);
        if let Some(rewritten) = rewrite_boot_line(body, add_loglevel, default_takes_console) {
            changed = true;
            out.push_str(&rewritten);
            if cr {
                out.push('\r');
            }
            out.push_str(nl);
        } else {
            out.push_str(line);
        }
    }
    changed.then_some(out)
}

fn rewrite_boot_line(
    line: &str,
    add_loglevel: bool,
    default_takes_console: bool,
) -> Option<String> {
    if let Some(rewritten) = rewrite_prefixed_line(line, "options", add_loglevel) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_assignment(
        line,
        "GRUB_CMDLINE_LINUX_DEFAULT=",
        add_loglevel,
        default_takes_console,
    ) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_assignment(line, "GRUB_CMDLINE_LINUX=", add_loglevel, true) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_assignment(line, "set kernelopts=", add_loglevel, true) {
        return Some(rewritten);
    }
    if let Some(rewritten) = rewrite_linux_line(line, add_loglevel) {
        return Some(rewritten);
    }
    if looks_like_raw_cmdline(line) {
        return rewrite_cmdline(line, add_loglevel, true);
    }
    None
}

fn indent_of(line: &str) -> &str {
    let rest = line.trim_start_matches([' ', '\t']);
    &line[..line.len() - rest.len()]
}

fn rewrite_prefixed_line(line: &str, prefix: &str, add_loglevel: bool) -> Option<String> {
    let indent = indent_of(line);
    let rest = line[indent.len()..].strip_prefix(prefix)?;
    if !rest.is_empty() && !rest.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let rewritten = rewrite_cmdline(rest, add_loglevel, true)?;
    Some(format!("{indent}{prefix} {rewritten}"))
}

fn rewrite_assignment(
    line: &str,
    key: &str,
    add_loglevel: bool,
    add_console: bool,
) -> Option<String> {
    let indent = indent_of(line);
    let rest = line[indent.len()..].strip_prefix(key)?;
    let (open, inner, close) =
        if let Some(inner) = rest.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            ("\"", inner, "\"")
        } else if let Some(inner) = rest.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            ("'", inner, "'")
        } else {
            ("", rest, "")
        };
    let rewritten = rewrite_cmdline(inner, add_loglevel, add_console)?;
    Some(format!("{indent}{key}{open}{rewritten}{close}"))
}

fn rewrite_linux_line(line: &str, add_loglevel: bool) -> Option<String> {
    let indent = indent_of(line);
    let rest = &line[indent.len()..];
    let command = if rest.starts_with("linuxefi") {
        "linuxefi"
    } else if rest.starts_with("linux") {
        "linux"
    } else {
        return None;
    };
    let after = rest.get(command.len()..)?;
    if after.is_empty() || !after.starts_with(|c: char| c.is_whitespace()) {
        return None;
    }
    let after = after.trim_start();
    let (kernel, args) = after.split_once(|c: char| c.is_whitespace())?;
    let rewritten = rewrite_cmdline(args, add_loglevel, true)?;
    Some(format!("{indent}{command} {kernel} {rewritten}"))
}

fn looks_like_raw_cmdline(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty()
        && !trimmed.starts_with('#')
        && trimmed
            .split_whitespace()
            .any(|token| silencer_key(token).is_some())
}

fn silencer_key(token: &str) -> Option<&str> {
    let key = token.split_once('=').map(|(key, _)| key).unwrap_or(token);
    SILENCE_KEYS.iter().copied().find(|name| *name == key)
}

fn rewrite_cmdline(args: &str, add_loglevel: bool, add_console: bool) -> Option<String> {
    let tokens: Vec<&str> = args.split_whitespace().collect();
    if tokens.is_empty() && !add_console {
        return None;
    }
    let mut kept = Vec::with_capacity(tokens.len() + 1 + SERIAL_CONSOLE.len());
    let mut removed = false;
    let mut has_loglevel = false;
    let mut has_console = false;
    for token in tokens {
        if silencer_key(token).is_some() {
            removed = true;
            continue;
        }
        if token == "debug" || token == "ignore_loglevel" || token.starts_with("loglevel=") {
            has_loglevel = true;
        }
        if token.starts_with("console=") {
            has_console = true;
        }
        kept.push(token);
    }
    let added = add_loglevel && !has_loglevel;
    if added {
        kept.push("loglevel=7");
    }
    let console_added = add_console && !has_console;
    if console_added {
        kept.extend_from_slice(SERIAL_CONSOLE);
    }
    if !removed && !added && !console_added {
        return None;
    }
    Some(kept.join(" "))
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

    #[test]
    fn cmdline_rewrite_strips_quiet_and_adds_loglevel() {
        assert_eq!(
            rewrite_cmdline("root=UUID=x ro rhgb quiet", true, true).as_deref(),
            Some("root=UUID=x ro loglevel=7 console=tty0 console=ttySAC0")
        );
        assert_eq!(
            rewrite_cmdline("root=UUID=x ro quiet", false, true).as_deref(),
            Some("root=UUID=x ro console=tty0 console=ttySAC0")
        );
        assert_eq!(
            rewrite_cmdline("root=UUID=x ro rhgb quiet", true, false).as_deref(),
            Some("root=UUID=x ro loglevel=7")
        );
        assert!(
            rewrite_cmdline(
                "root=UUID=x ro loglevel=7 console=tty0 console=ttySAC0",
                true,
                true
            )
            .is_none()
        );
        assert_eq!(
            rewrite_cmdline("root=UUID=x ro quiet console=ttyAMA0", true, true).as_deref(),
            Some("root=UUID=x ro console=ttyAMA0 loglevel=7")
        );
        assert_eq!(
            rewrite_assignment(
                r#"GRUB_CMDLINE_LINUX_DEFAULT="rhgb quiet rootflags=subvol=root""#,
                "GRUB_CMDLINE_LINUX_DEFAULT=",
                true,
                true
            )
            .as_deref(),
            Some(
                r#"GRUB_CMDLINE_LINUX_DEFAULT="rootflags=subvol=root loglevel=7 console=tty0 console=ttySAC0""#
            )
        );
        assert_eq!(
            rewrite_boot_line(
                r#"  set kernelopts="root=UUID=x ro rootflags=subvol=root  rhgb quiet""#,
                true,
                false
            )
            .as_deref(),
            Some(
                r#"  set kernelopts="root=UUID=x ro rootflags=subvol=root loglevel=7 console=tty0 console=ttySAC0""#
            )
        );
        assert_eq!(
            rewrite_linux_line("\tlinux\t/vmlinuz-asahi root=UUID=x ro rhgb quiet", false)
                .as_deref(),
            Some("\tlinux /vmlinuz-asahi root=UUID=x ro console=tty0 console=ttySAC0")
        );
        assert_eq!(
            rewrite_prefixed_line("options root=UUID=x ro rhgb quiet", "options", true).as_deref(),
            Some("options root=UUID=x ro loglevel=7 console=tty0 console=ttySAC0")
        );
    }

    #[test]
    fn default_grub_carries_the_serial_console_once() {
        let both = "GRUB_TIMEOUT=5\n\
GRUB_CMDLINE_LINUX=\"rhgb quiet\"\n\
GRUB_CMDLINE_LINUX_DEFAULT=\"rootflags=subvol=root quiet\"\n\
GRUB_ENABLE_BLSCFG=true\n";
        assert_eq!(
            rewrite_boot_text(both, true).as_deref(),
            Some(
                "GRUB_TIMEOUT=5\n\
GRUB_CMDLINE_LINUX=\"loglevel=7 console=tty0 console=ttySAC0\"\n\
GRUB_CMDLINE_LINUX_DEFAULT=\"rootflags=subvol=root loglevel=7\"\n\
GRUB_ENABLE_BLSCFG=true\n"
            )
        );

        let empty_linux = "GRUB_CMDLINE_LINUX=\"\"\n\
GRUB_CMDLINE_LINUX_DEFAULT=\"rhgb quiet rootflags=subvol=root\"\n";
        assert_eq!(
            rewrite_boot_text(empty_linux, true).as_deref(),
            Some(
                "GRUB_CMDLINE_LINUX=\"loglevel=7 console=tty0 console=ttySAC0\"\n\
GRUB_CMDLINE_LINUX_DEFAULT=\"rootflags=subvol=root loglevel=7\"\n"
            )
        );

        let default_only = "GRUB_CMDLINE_LINUX_DEFAULT=\"rhgb quiet rootflags=subvol=root\"\n";
        assert_eq!(
            rewrite_boot_text(default_only, true).as_deref(),
            Some(
                "GRUB_CMDLINE_LINUX_DEFAULT=\"rootflags=subvol=root loglevel=7 console=tty0 console=ttySAC0\"\n"
            )
        );
    }

    fn boot_console_image(cfg: &str) -> Vec<u8> {
        let mut image = fixture("10+2");
        fn u16w(b: &mut [u8], at: usize, value: u16) {
            b[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        fn u32w(b: &mut [u8], at: usize, value: u32) {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        u32w(&mut image, 4116, 16);
        image[4128..4132].copy_from_slice(&4u32.to_le_bytes());
        u16w(&mut image, 4132, 16);
        image[4134] = 8;
        image[4136..4144].copy_from_slice(b"grub.cfg");
        // A regular file named "boot" must not make /boot/grub2/grub.cfg fail the rewrite.
        image[4144..4148].copy_from_slice(&3u32.to_le_bytes());
        u16w(&mut image, 4148, 976);
        image[4150] = 4;
        image[4152..4156].copy_from_slice(b"boot");
        let at = 3072 + 3 * 128;
        u16w(&mut image, at, 0x8000);
        u32w(&mut image, at + 4, cfg.len() as u32);
        u32w(&mut image, at + 32, 0x80000);
        u16w(&mut image, at + 40, 0xf30a);
        u16w(&mut image, at + 42, 1);
        u16w(&mut image, at + 44, 4);
        u16w(&mut image, at + 56, 1);
        u32w(&mut image, at + 60, 6);
        image[6144..7168].fill(b' ');
        image[6144..6144 + cfg.len()].copy_from_slice(cfg.as_bytes());
        image
    }

    #[test]
    fn ext4_verbose_rewrite_keeps_file_size_and_strips_quiet() {
        let cfg = "linux /vmlinuz root=UUID=x ro rhgb quiet\n";
        let original = boot_console_image(cfg);
        let mut source = std::io::Cursor::new(original.clone());
        assert!(enable_verbose_kernel(&mut source).unwrap());
        let output = source.into_inner();
        assert_eq!(output.len(), original.len());
        let text = std::str::from_utf8(&output[6144..7168]).unwrap();
        assert!(!text.contains("quiet"));
        assert!(!text.contains("rhgb"));
        assert!(text.contains("loglevel=7"));
        assert!(text.contains("linux /vmlinuz root=UUID=x ro"));
        assert!(!enable_verbose_kernel(&mut std::io::Cursor::new(output)).unwrap());

        let mut full = original.clone();
        full[BLS_INODE + 4..BLS_INODE + 8].copy_from_slice(&1024u32.to_le_bytes());
        let mut source = std::io::Cursor::new(full.clone());
        let refusal = enable_verbose_kernel(&mut source).unwrap_err();
        assert!(refusal.contains("does not fit"), "{refusal}");
        assert!(source.into_inner() == full);
    }

    #[test]
    fn verbose_rewrite_skips_non_directory_path_components() {
        let original = fixture("10+2");
        let mut source = std::io::Cursor::new(original.clone());
        assert!(!enable_verbose_kernel(&mut source).unwrap());
        assert_eq!(source.into_inner(), original);
    }

    #[test]
    fn create_disc_keeps_packaged_boot_console_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let boot = dir.path().join("boot.img");
        let cfg = "linux /vmlinuz root=UUID=x ro rhgb quiet\n";
        let original = boot_console_image(cfg);
        std::fs::write(&boot, &original).unwrap();
        let mut artifacts = crate::asahi_ops::Artifacts::memory(
            b"KERN".to_vec(),
            b"M1N1".to_vec(),
            b"ROOT".to_vec(),
        );
        artifacts.boot_path = Some(boot.clone());
        let mut stage1 = vec![0u8; 2048];
        stage1[..12].copy_from_slice(b"##m1n1_ver##");
        artifacts.m1n1_stage1 = stage1;
        crate::asahi_ops::create_qcow2_disc(
            &dir.path().join("asahi.qcow2"),
            &artifacts,
            8 << 20,
            "m1n1/boot.bin",
            "Asahi Linux",
        )
        .unwrap();
        let normal = std::fs::read(&boot).unwrap();
        assert!(
            normal == original,
            "default build changed the package boot image"
        );
        crate::asahi_ops::create_qcow2_disc_with_options(
            &dir.path().join("verbose.qcow2"),
            &artifacts,
            8 << 20,
            "m1n1/boot.bin",
            "Asahi Linux",
            &crate::asahi_ops::DiscOptions {
                kernel_console: crate::asahi_ops::KernelConsole::Verbose,
            },
            |_| {},
        )
        .unwrap();
        let verbose = std::fs::read(&boot).unwrap();
        let text = std::str::from_utf8(&verbose[6144..7168]).unwrap();
        assert!(!text.contains("quiet"), "{text}");
        assert!(!text.contains("rhgb"), "{text}");
        assert!(text.contains("loglevel=7"), "{text}");
    }

    const FEDORA_BLS_ENTRY: &str = "title Fedora Linux Asahi Remix (7.1.6-400.asahi.fc44.aarch64+16k) 44 (Workstation Edition)\n\
version 7.1.6-400.asahi.fc44.aarch64+16k\n\
linux /vmlinuz-7.1.6-400.asahi.fc44.aarch64+16k\n\
initrd /initramfs-7.1.6-400.asahi.fc44.aarch64+16k.img $tuned_initrd\n\
options rhgb quiet root=UUID=36431cc9-a4f5-4c93-9740-ea1e09fce299 rootflags=subvol=root\n\
grub_users $grub_users\n\
grub_arg --unrestricted\n\
grub_class fedora-asahi-remix\n";

    const FEDORA_BLS_OPTIONS: &str =
        "options rhgb quiet root=UUID=36431cc9-a4f5-4c93-9740-ea1e09fce299 rootflags=subvol=root";

    const VERBOSE_BLS_OPTIONS: &str = "options root=UUID=36431cc9-a4f5-4c93-9740-ea1e09fce299 rootflags=subvol=root loglevel=7 console=tty0 console=ttySAC0";

    const BLS_INODE: usize = 3072 + 3 * 128;

    /// The boot image fixture with its one boot file holding a Fedora BLS entry and sized
    /// to the entry, so the verbose line has to grow into the rest of its block.
    fn bls_image(checksum_uuid: Option<[u8; 16]>) -> Vec<u8> {
        let mut image = boot_console_image(FEDORA_BLS_ENTRY);
        image[BLS_INODE + 4..BLS_INODE + 8]
            .copy_from_slice(&(FEDORA_BLS_ENTRY.len() as u32).to_le_bytes());
        if let Some(uuid) = checksum_uuid {
            image[1024 + 101] |= 0x04;
            image[1024 + 0x175] = 1;
            image[1024 + 0x68..1024 + 0x78].copy_from_slice(&uuid);
            seal_bls_inode(&mut image, uuid);
        }
        image
    }

    fn seal_bls_inode(image: &mut [u8], uuid: [u8; 16]) {
        let seed = crate::crypto::crc32::crc32c_update(u32::MAX, &uuid);
        let (checksum, _) =
            crate::ext4_boot::inode_checksum(seed, 4, &image[BLS_INODE..BLS_INODE + 128]).unwrap();
        image[BLS_INODE + 0x7c..BLS_INODE + 0x7e].copy_from_slice(&(checksum as u16).to_le_bytes());
    }

    fn boot_file(image: &[u8]) -> String {
        let mut cursor = std::io::Cursor::new(image);
        let mut ext4 = crate::ext4_boot::Ext4::open(&mut cursor).unwrap().unwrap();
        String::from_utf8(ext4.file("/grub2/grub.cfg").unwrap().unwrap().bytes).unwrap()
    }

    fn build_with(boot: &std::path::Path, console: crate::asahi_ops::KernelConsole) {
        let dir = tempfile::tempdir().unwrap();
        let mut artifacts = crate::asahi_ops::Artifacts::memory(
            b"KERN".to_vec(),
            b"M1N1".to_vec(),
            b"ROOT".to_vec(),
        );
        artifacts.boot_path = Some(boot.to_path_buf());
        let mut stage1 = vec![0u8; 2048];
        stage1[..12].copy_from_slice(b"##m1n1_ver##");
        artifacts.m1n1_stage1 = stage1;
        crate::asahi_ops::create_qcow2_disc_with_options(
            &dir.path().join("asahi.qcow2"),
            &artifacts,
            8 << 20,
            "m1n1/boot.bin",
            "Asahi Linux",
            &crate::asahi_ops::DiscOptions {
                kernel_console: console,
            },
            |_| {},
        )
        .unwrap();
    }

    #[test]
    fn verbose_and_normal_boot_produce_expected_options_lines() {
        let dir = tempfile::tempdir().unwrap();
        let boot = dir.path().join("boot.img");
        let original = bls_image(None);
        assert_eq!(boot_file(&original), FEDORA_BLS_ENTRY);

        std::fs::write(&boot, &original).unwrap();
        build_with(&boot, crate::asahi_ops::KernelConsole::Verbose);
        let verbose = boot_file(&std::fs::read(&boot).unwrap());
        assert_eq!(
            verbose,
            FEDORA_BLS_ENTRY.replace(FEDORA_BLS_OPTIONS, VERBOSE_BLS_OPTIONS)
        );

        std::fs::write(&boot, &original).unwrap();
        build_with(&boot, crate::asahi_ops::KernelConsole::Normal);
        let normal = std::fs::read(&boot).unwrap();
        assert_eq!(boot_file(&normal), FEDORA_BLS_ENTRY);
        assert!(
            normal == original,
            "normal boot changed the package boot image"
        );
    }

    #[test]
    fn verbose_growth_reseals_checksummed_inode_and_refuses_a_bad_seal() {
        let uuid = *b"fedora-asahi-uid";
        let original = bls_image(Some(uuid));
        let mut source = std::io::Cursor::new(original.clone());
        assert!(enable_verbose_kernel(&mut source).unwrap());
        let output = source.into_inner();
        assert_eq!(
            boot_file(&output),
            FEDORA_BLS_ENTRY.replace(FEDORA_BLS_OPTIONS, VERBOSE_BLS_OPTIONS)
        );
        let mut resealed = output.clone();
        seal_bls_inode(&mut resealed, uuid);
        assert!(
            resealed == output,
            "grown inode does not carry its recomputed checksum"
        );

        let mut tampered = original.clone();
        tampered[BLS_INODE + 0x7c] ^= 0xff;
        let mut source = std::io::Cursor::new(tampered.clone());
        let refusal = enable_verbose_kernel(&mut source).unwrap_err();
        assert!(
            refusal.contains("inode checksum does not verify"),
            "{refusal}"
        );
        assert!(source.into_inner() == tampered);
    }
}
