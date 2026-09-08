use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Device,
    Other,
}

impl FileKind {
    pub fn label(self) -> &'static str {
        match self {
            FileKind::File => "file",
            FileKind::Directory => "folder",
            FileKind::Symlink => "alias",
            FileKind::Device => "device",
            FileKind::Other => "item",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub name: String,
    pub kind: FileKind,
    pub size: Option<u64>,
    pub modified: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ClipWatch {
    pub raw: String,
    pub file: Option<FileInfo>,
    last_check: Option<Instant>,
}

impl ClipWatch {
    pub fn refresh(&mut self) {
        if self
            .last_check
            .is_some_and(|at| at.elapsed() < Duration::from_millis(400))
        {
            return;
        }
        self.last_check = Some(Instant::now());
        let raw = read_clipboard();
        if raw == self.raw {
            return;
        }
        self.raw = raw;
        self.file = inspect(&self.raw);
    }

    pub fn set_file(&mut self, file: FileInfo) {
        self.raw = file.path.to_string_lossy().into_owned();
        self.file = Some(file);
        self.last_check = Some(Instant::now());
    }

    pub fn force_refresh(&mut self) {
        self.last_check = None;
        self.refresh();
    }
}

pub fn inspect(raw: &str) -> Option<FileInfo> {
    let path = normalize_clip(raw)?;
    let meta = std::fs::symlink_metadata(&path).ok()?;
    let kind = if meta.file_type().is_symlink() {
        FileKind::Symlink
    } else if meta.file_type().is_dir() {
        FileKind::Directory
    } else if is_device(&meta) {
        FileKind::Device
    } else if meta.file_type().is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };

    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| path.to_string_lossy().into_owned());

    let size = match kind {
        FileKind::Directory => None,
        _ => Some(meta.len()),
    };

    Some(FileInfo {
        path,
        name,
        kind,
        size,
        modified: meta.modified().ok().and_then(format_modified),
    })
}

fn normalize_clip(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    let first = trimmed.lines().next().unwrap_or("").trim();
    let stripped = strip_quotes(first);
    if stripped.is_empty() {
        return None;
    }

    let mut text = stripped.to_string();
    if let Some(rest) = text.strip_prefix("file://") {
        text = percent_decode(rest);
    }
    if let Some(home) = std::env::var_os("HOME")
        && let Some(rest) = text.strip_prefix("~/")
    {
        let mut path = PathBuf::from(home);
        path.push(rest);
        return path.canonicalize().ok().or(Some(path));
    }

    let path = PathBuf::from(&text);
    if path.exists() {
        Some(path.canonicalize().unwrap_or(path))
    } else {
        None
    }
}

fn strip_quotes(s: &str) -> &str {
    match (s.chars().next(), s.chars().last()) {
        (Some('"'), Some('"')) if s.len() >= 2 => &s[1..s.len() - 1],
        (Some('\''), Some('\'')) if s.len() >= 2 => &s[1..s.len() - 1],
        _ => s,
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(value) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
        {
            out.push(value);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn is_device(meta: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        meta.file_type().is_block_device() || meta.file_type().is_char_device()
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        false
    }
}

fn format_modified(time: SystemTime) -> Option<String> {
    let elapsed = SystemTime::now().duration_since(time).ok()?;
    let secs = elapsed.as_secs();
    Some(if secs < 60 {
        "just now".into()
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else if secs < 86_400 {
        format!("{} hours ago", secs / 3600)
    } else if secs < 86_400 * 14 {
        format!("{} days ago", secs / 86_400)
    } else {
        format!("{} weeks ago", secs / (86_400 * 7))
    })
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(target_os = "macos")]
fn read_clipboard() -> String {
    if let Some(path) = osascript_file()
        && !path.is_empty()
    {
        return path;
    }
    pbpaste()
}

#[cfg(target_os = "macos")]
fn osascript_file() -> Option<String> {
    let script = r#"
try
    POSIX path of (the clipboard as «class furl»)
on error
    try
        POSIX path of (the clipboard as alias)
    on error
        try
            the clipboard as text
        on error
            ""
        end try
    end try
end try
"#;
    let output = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(target_os = "macos")]
fn pbpaste() -> String {
    Command::new("pbpaste")
        .output()
        .ok()
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

#[cfg(not(target_os = "macos"))]
fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(cmd).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(windows)]
fn read_clipboard() -> String {
    run_stdout(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"],
    )
    .unwrap_or_default()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn read_clipboard() -> String {
    if let Some(path) = unix_uri_file()
        && !path.is_empty()
    {
        return path;
    }
    unix_text().unwrap_or_default()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn unix_uri_file() -> Option<String> {
    let list = wayland_uri_list().or_else(x11_uri_list)?;
    uri_list_first_path(&list)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn unix_text() -> Option<String> {
    wayland_text().or_else(x11_text)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn has_wayland() -> bool {
    std::env::var_os("WAYLAND_DISPLAY").is_some()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn has_x11() -> bool {
    std::env::var_os("DISPLAY").is_some()
}

#[cfg(not(any(target_os = "macos", windows)))]
fn wayland_uri_list() -> Option<String> {
    if !has_wayland() {
        return None;
    }
    run_stdout("wl-paste", &["--no-newline", "--type", "text/uri-list"])
}

#[cfg(not(any(target_os = "macos", windows)))]
fn wayland_text() -> Option<String> {
    if !has_wayland() {
        return None;
    }
    run_stdout("wl-paste", &["--no-newline"])
}

#[cfg(not(any(target_os = "macos", windows)))]
fn x11_uri_list() -> Option<String> {
    if !has_x11() {
        return None;
    }
    run_stdout(
        "xclip",
        &["-selection", "clipboard", "-t", "text/uri-list", "-o"],
    )
}

#[cfg(not(any(target_os = "macos", windows)))]
fn x11_text() -> Option<String> {
    if !has_x11() {
        return None;
    }
    run_stdout("xclip", &["-selection", "clipboard", "-o"])
        .or_else(|| run_stdout("xsel", &["--clipboard", "--output"]))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn uri_list_first_path(list: &str) -> Option<String> {
    for line in list.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let path = match line.strip_prefix("file://") {
            Some(rest) => percent_decode(rest),
            None => line.to_string(),
        };
        if !path.is_empty() {
            return Some(path);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inspect_rejects_plain_text() {
        assert!(inspect("hello clipboard").is_none());
        assert!(inspect("").is_none());
    }

    #[test]
    fn format_size_scales() {
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(2048), "2.0 KB");
    }

    #[test]
    fn inspect_tmp_if_present() {
        if std::path::Path::new("/tmp").exists() {
            let info = inspect("/tmp").expect("tmp");
            assert_eq!(info.kind, FileKind::Directory);
            assert!(inspect("file:///tmp").is_some());
            assert!(inspect("  \"/tmp\"  ").is_some());
        }
    }
}

#[cfg(all(test, not(any(target_os = "macos", windows))))]
mod unix_backend_tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn uri_list_first_path_decodes_file_uri() {
        let list = "file:///tmp/example%20file.txt\n";
        assert_eq!(
            uri_list_first_path(list).as_deref(),
            Some("/tmp/example file.txt")
        );
    }

    #[test]
    fn uri_list_first_path_skips_comments_and_blank_lines() {
        let list = "# a comment\r\n\nfile:///tmp/a\n";
        assert_eq!(uri_list_first_path(list).as_deref(), Some("/tmp/a"));
    }

    #[test]
    fn uri_list_first_path_returns_none_for_empty_or_comments_only() {
        assert!(uri_list_first_path("").is_none());
        assert!(uri_list_first_path("# nothing here\n\n").is_none());
    }

    #[test]
    fn uri_list_first_path_passes_through_non_file_uri() {
        let list = "http://example.com/x\n";
        assert_eq!(
            uri_list_first_path(list).as_deref(),
            Some("http://example.com/x")
        );
    }

    #[test]
    fn uri_list_first_path_takes_first_of_multiple_entries() {
        let list = "file:///tmp/first\nfile:///tmp/second\n";
        assert_eq!(uri_list_first_path(list).as_deref(), Some("/tmp/first"));
    }

    #[test]
    fn wayland_detection_follows_env_var() {
        let _guard = env_lock().lock().unwrap();
        let previous = std::env::var_os("WAYLAND_DISPLAY");
        // SAFETY: single-threaded within the `env_lock` critical section;
        // no other code in this process reads/writes this var concurrently.
        unsafe {
            std::env::remove_var("WAYLAND_DISPLAY");
        }
        assert!(!has_wayland());
        unsafe {
            std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
        }
        assert!(has_wayland());
        unsafe {
            match &previous {
                Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
                None => std::env::remove_var("WAYLAND_DISPLAY"),
            }
        }
    }

    #[test]
    fn x11_detection_follows_env_var() {
        let _guard = env_lock().lock().unwrap();
        let previous = std::env::var_os("DISPLAY");
        // SAFETY: single-threaded within the `env_lock` critical section;
        // no other code in this process reads/writes this var concurrently.
        unsafe {
            std::env::remove_var("DISPLAY");
        }
        assert!(!has_x11());
        unsafe {
            std::env::set_var("DISPLAY", ":0");
        }
        assert!(has_x11());
        unsafe {
            match &previous {
                Some(v) => std::env::set_var("DISPLAY", v),
                None => std::env::remove_var("DISPLAY"),
            }
        }
    }

    #[test]
    fn backends_are_skipped_when_session_missing() {
        let _wayland_guard = env_lock().lock().unwrap();
        let previous_wayland = std::env::var_os("WAYLAND_DISPLAY");
        let previous_display = std::env::var_os("DISPLAY");
        // SAFETY: single-threaded within the `env_lock` critical section.
        unsafe {
            std::env::remove_var("WAYLAND_DISPLAY");
            std::env::remove_var("DISPLAY");
        }
        assert!(wayland_uri_list().is_none());
        assert!(wayland_text().is_none());
        assert!(x11_uri_list().is_none());
        assert!(x11_text().is_none());
        unsafe {
            match &previous_wayland {
                Some(v) => std::env::set_var("WAYLAND_DISPLAY", v),
                None => std::env::remove_var("WAYLAND_DISPLAY"),
            }
            match &previous_display {
                Some(v) => std::env::set_var("DISPLAY", v),
                None => std::env::remove_var("DISPLAY"),
            }
        }
    }
}
