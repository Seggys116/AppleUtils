use std::fmt;
use std::io::{ErrorKind, Read, Write};

/// The guest's extractor takes the cpio arm only on a zero filter code, so the magic must be in the clear.
pub const CPIO_MAGIC: &[u8; 6] = b"070707";

pub const CPIO_HEADER_BYTES: usize = 76;

pub const CPIO_TRAILER_PATH: &str = "TRAILER!!!";

pub const MODE_TYPE_REGULAR: u32 = 0o100_000;

pub const MODE_TYPE_DIRECTORY: u32 = 0o040_000;

pub const MODE_TYPE_SYMLINK: u32 = 0o120_000;

pub const MODE_PERMISSION_MASK: u32 = 0o7777;

const COPY_BUFFER_BYTES: usize = 64 * 1024;

const NARROW_FIELD: usize = 6;

const WIDE_FIELD: usize = 11;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CpioFileType {
    Directory,
    RegularFile,
    Symlink,
}

impl CpioFileType {
    #[must_use]
    pub fn mode_type_bits(self) -> u32 {
        match self {
            Self::Directory => MODE_TYPE_DIRECTORY,
            Self::RegularFile => MODE_TYPE_REGULAR,
            Self::Symlink => MODE_TYPE_SYMLINK,
        }
    }

    #[must_use]
    pub fn link_count(self) -> u32 {
        1
    }

    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular file",
            Self::Symlink => "symlink",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpioFileMeta {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpioBody {
    Empty,
    LinkTarget(String),
    Contents(Vec<u8>),
}

impl CpioBody {
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Empty => "an empty body",
            Self::LinkTarget(_) => "a link target",
            Self::Contents(_) => "file contents",
        }
    }

    #[must_use]
    pub fn declared_size(&self) -> u64 {
        match self {
            Self::Empty => 0,
            Self::LinkTarget(target) => target.len() as u64,
            Self::Contents(bytes) => bytes.len() as u64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CpioEntry {
    pub path: String,
    pub file_type: CpioFileType,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub body: CpioBody,
}

impl CpioEntry {
    #[must_use]
    pub fn directory(path: impl Into<String>, mode: u32, uid: u32, gid: u32, mtime: u64) -> Self {
        Self {
            path: path.into(),
            file_type: CpioFileType::Directory,
            mode,
            uid,
            gid,
            mtime,
            body: CpioBody::Empty,
        }
    }

    #[must_use]
    pub fn symlink(
        path: impl Into<String>,
        target: impl Into<String>,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: u64,
    ) -> Self {
        Self {
            path: path.into(),
            file_type: CpioFileType::Symlink,
            mode,
            uid,
            gid,
            mtime,
            body: CpioBody::LinkTarget(target.into()),
        }
    }

    #[must_use]
    pub fn regular_file(
        path: impl Into<String>,
        contents: Vec<u8>,
        mode: u32,
        uid: u32,
        gid: u32,
        mtime: u64,
    ) -> Self {
        Self {
            path: path.into(),
            file_type: CpioFileType::RegularFile,
            mode,
            uid,
            gid,
            mtime,
            body: CpioBody::Contents(contents),
        }
    }
}

#[derive(Debug)]
pub enum CpioError {
    FieldTooLarge {
        field: &'static str,
        value: u64,
        width: usize,
    },
    EmptyPath,
    NulInPath {
        path: String,
        offset: usize,
    },
    NulInLinkTarget {
        path: String,
        target: String,
        offset: usize,
    },
    ModeOutsidePermissionMask {
        path: String,
        mode: u32,
    },
    BodyMismatch {
        path: String,
        file_type: CpioFileType,
        body: &'static str,
    },
    SourceTooShort {
        path: String,
        expected: u64,
        copied: u64,
    },
    SourceTooLong {
        path: String,
        expected: u64,
    },
    Io(std::io::Error),
}

impl fmt::Display for CpioError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FieldTooLarge {
                field,
                value,
                width,
            } => write!(
                formatter,
                "the cpio {field} field holds {width} octal digits and {value} needs more, so it cannot be written without being truncated into a different number"
            ),
            Self::EmptyPath => formatter.write_str("a cpio member cannot have an empty path"),
            Self::NulInPath { path, offset } => write!(
                formatter,
                "the path {path:?} holds a NUL at offset {offset}, which would end it early and leave the rest of it being read as the member's body"
            ),
            Self::NulInLinkTarget {
                path,
                target,
                offset,
            } => write!(
                formatter,
                "the link target {target:?} of {path} holds a NUL at offset {offset}, which would not survive the round trip through the archive"
            ),
            Self::ModeOutsidePermissionMask { path, mode } => write!(
                formatter,
                "the mode 0o{mode:o} given for {path} carries bits outside the permission mask 0o{MODE_PERMISSION_MASK:o}: the file type bits come from the entry's own type and passing a whole st_mode here ORs two types together"
            ),
            Self::BodyMismatch {
                path,
                file_type,
                body,
            } => write!(
                formatter,
                "{path} is a {} but carries {body}",
                file_type.describe()
            ),
            Self::SourceTooShort {
                path,
                expected,
                copied,
            } => write!(
                formatter,
                "{path} declared {expected} bytes and the source gave {copied}: the archive is desynchronised from this point and every later member would be read out of the wrong offset"
            ),
            Self::SourceTooLong { path, expected } => write!(
                formatter,
                "{path} declared {expected} bytes and the source still had more: the declared length is not the length of the thing being archived"
            ),
            Self::Io(error) => write!(formatter, "writing the archive: {error}"),
        }
    }
}

impl std::error::Error for CpioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CpioError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

fn push_octal(
    header: &mut Vec<u8>,
    field: &'static str,
    value: u64,
    width: usize,
) -> Result<(), CpioError> {
    let digits = format!("{value:o}");
    if digits.len() > width {
        return Err(CpioError::FieldTooLarge {
            field,
            value,
            width,
        });
    }
    for _ in digits.len()..width {
        header.push(b'0');
    }
    header.extend_from_slice(digits.as_bytes());
    Ok(())
}

fn validate_path(path: &str) -> Result<u64, CpioError> {
    if path.is_empty() {
        return Err(CpioError::EmptyPath);
    }
    if let Some(offset) = path.as_bytes().iter().position(|byte| *byte == 0) {
        return Err(CpioError::NulInPath {
            path: path.to_string(),
            offset,
        });
    }
    Ok(path.len() as u64 + 1)
}

fn build_header(
    path: &str,
    ino: u64,
    meta: CpioFileMeta,
    nlink: u32,
    filesize: u64,
) -> Result<Vec<u8>, CpioError> {
    let namesize = validate_path(path)?;
    let mut header = Vec::with_capacity(CPIO_HEADER_BYTES);
    header.extend_from_slice(CPIO_MAGIC);
    push_octal(&mut header, "dev", 0, NARROW_FIELD)?;
    push_octal(&mut header, "ino", ino, NARROW_FIELD)?;
    push_octal(&mut header, "mode", u64::from(meta.mode), NARROW_FIELD)?;
    push_octal(&mut header, "uid", u64::from(meta.uid), NARROW_FIELD)?;
    push_octal(&mut header, "gid", u64::from(meta.gid), NARROW_FIELD)?;
    push_octal(&mut header, "nlink", u64::from(nlink), NARROW_FIELD)?;
    push_octal(&mut header, "rdev", 0, NARROW_FIELD)?;
    push_octal(&mut header, "mtime", meta.mtime, WIDE_FIELD)?;
    push_octal(&mut header, "namesize", namesize, NARROW_FIELD)?;
    push_octal(&mut header, "filesize", filesize, WIDE_FIELD)?;
    Ok(header)
}

pub struct CpioWriter<W: Write> {
    out: W,
    bytes_written: u64,
    entries_written: u64,
    next_inode: u64,
}

impl<W: Write> CpioWriter<W> {
    #[must_use]
    pub fn new(out: W) -> Self {
        Self {
            out,
            bytes_written: 0,
            entries_written: 0,
            next_inode: 1,
        }
    }

    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    #[must_use]
    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }

    #[must_use]
    pub fn into_inner(self) -> W {
        self.out
    }

    pub fn write_directory(&mut self, path: &str, meta: CpioFileMeta) -> Result<(), CpioError> {
        self.write_member(path, CpioFileType::Directory, meta, 0)
    }

    pub fn write_symlink(
        &mut self,
        path: &str,
        target: &str,
        meta: CpioFileMeta,
    ) -> Result<(), CpioError> {
        if let Some(offset) = target.as_bytes().iter().position(|byte| *byte == 0) {
            return Err(CpioError::NulInLinkTarget {
                path: path.to_string(),
                target: target.to_string(),
                offset,
            });
        }
        self.write_member(path, CpioFileType::Symlink, meta, target.len() as u64)?;
        self.emit(target.as_bytes())
    }

    pub fn write_file<R: Read>(
        &mut self,
        path: &str,
        len: u64,
        data: &mut R,
        meta: CpioFileMeta,
    ) -> Result<(), CpioError> {
        self.write_member(path, CpioFileType::RegularFile, meta, len)?;

        let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
        let mut remaining = len;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(COPY_BUFFER_BYTES as u64))
                .unwrap_or(COPY_BUFFER_BYTES);
            match data.read(&mut buffer[..want]) {
                Ok(0) => {
                    return Err(CpioError::SourceTooShort {
                        path: path.to_string(),
                        expected: len,
                        copied: len - remaining,
                    });
                }
                Ok(read) => {
                    self.emit(&buffer[..read])?;
                    remaining -= read as u64;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(CpioError::Io(error)),
            }
        }

        let mut overrun = [0u8; 1];
        loop {
            match data.read(&mut overrun) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(CpioError::SourceTooLong {
                        path: path.to_string(),
                        expected: len,
                    });
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => return Err(CpioError::Io(error)),
            }
        }
    }

    pub fn write_entry(&mut self, entry: &CpioEntry) -> Result<(), CpioError> {
        let meta = CpioFileMeta {
            mode: entry.mode,
            uid: entry.uid,
            gid: entry.gid,
            mtime: entry.mtime,
        };
        match (entry.file_type, &entry.body) {
            (CpioFileType::Directory, CpioBody::Empty) => self.write_directory(&entry.path, meta),
            (CpioFileType::Symlink, CpioBody::LinkTarget(target)) => {
                self.write_symlink(&entry.path, target, meta)
            }
            (CpioFileType::RegularFile, CpioBody::Contents(bytes)) => {
                let mut source = bytes.as_slice();
                self.write_file(&entry.path, bytes.len() as u64, &mut source, meta)
            }
            (file_type, body) => Err(CpioError::BodyMismatch {
                path: entry.path.clone(),
                file_type,
                body: body.describe(),
            }),
        }
    }

    pub fn finish(&mut self) -> Result<(), CpioError> {
        let header = build_header(
            CPIO_TRAILER_PATH,
            0,
            CpioFileMeta {
                mode: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            1,
            0,
        )?;
        self.emit(&header)?;
        self.emit(CPIO_TRAILER_PATH.as_bytes())?;
        self.emit(&[0])?;
        self.out.flush().map_err(CpioError::Io)
    }

    fn write_member(
        &mut self,
        path: &str,
        file_type: CpioFileType,
        meta: CpioFileMeta,
        filesize: u64,
    ) -> Result<(), CpioError> {
        if meta.mode & !MODE_PERMISSION_MASK != 0 {
            return Err(CpioError::ModeOutsidePermissionMask {
                path: path.to_string(),
                mode: meta.mode,
            });
        }
        let header = build_header(
            path,
            self.next_inode,
            CpioFileMeta {
                mode: file_type.mode_type_bits() | meta.mode,
                ..meta
            },
            file_type.link_count(),
            filesize,
        )?;
        self.emit(&header)?;
        self.emit(path.as_bytes())?;
        self.emit(&[0])?;
        self.next_inode += 1;
        self.entries_written += 1;
        Ok(())
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), CpioError> {
        self.out.write_all(bytes).map_err(CpioError::Io)?;
        self.bytes_written += bytes.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(mode: u32, mtime: u64) -> CpioFileMeta {
        CpioFileMeta {
            mode,
            uid: 0,
            gid: 0,
            mtime,
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    struct ParsedEntry {
        path: String,
        ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u32,
        mtime: u64,
        body: Vec<u8>,
    }

    fn parse_octal(field: &[u8]) -> u64 {
        let text = std::str::from_utf8(field).expect("header fields are ASCII");
        u64::from_str_radix(text, 8).expect("header fields are octal")
    }

    fn parse_archive(bytes: &[u8]) -> Vec<ParsedEntry> {
        let mut entries = Vec::new();
        let mut offset = 0usize;
        loop {
            assert!(
                offset + CPIO_HEADER_BYTES <= bytes.len(),
                "the archive ended inside a header"
            );
            let header = &bytes[offset..offset + CPIO_HEADER_BYTES];
            assert_eq!(&header[0..6], CPIO_MAGIC);
            assert_eq!(parse_octal(&header[6..12]), 0, "dev is always zero");
            assert_eq!(parse_octal(&header[42..48]), 0, "rdev is always zero");
            let ino = parse_octal(&header[12..18]);
            let mode = parse_octal(&header[18..24]) as u32;
            let uid = parse_octal(&header[24..30]) as u32;
            let gid = parse_octal(&header[30..36]) as u32;
            let nlink = parse_octal(&header[36..42]) as u32;
            let mtime = parse_octal(&header[48..59]);
            let namesize = parse_octal(&header[59..65]) as usize;
            let filesize = parse_octal(&header[65..76]) as usize;
            offset += CPIO_HEADER_BYTES;

            assert!(namesize >= 1, "namesize covers at least the NUL");
            let path = String::from_utf8(bytes[offset..offset + namesize - 1].to_vec())
                .expect("paths are UTF-8 here");
            assert_eq!(
                bytes[offset + namesize - 1],
                0,
                "the path is NUL terminated"
            );
            offset += namesize;

            let body = bytes[offset..offset + filesize].to_vec();
            offset += filesize;

            if path == CPIO_TRAILER_PATH {
                assert_eq!(offset, bytes.len(), "nothing follows the trailer");
                return entries;
            }
            entries.push(ParsedEntry {
                path,
                ino,
                mode,
                uid,
                gid,
                nlink,
                mtime,
                body,
            });
        }
    }

    #[test]
    fn a_header_is_seventy_six_bytes_and_opens_with_the_portable_magic() {
        let header = build_header(
            "etc/rc",
            1,
            CpioFileMeta {
                mode: MODE_TYPE_REGULAR | 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            1,
            0,
        )
        .expect("the header fits");
        assert_eq!(header.len(), CPIO_HEADER_BYTES);
        assert_eq!(&header[0..6], b"070707");
    }

    #[test]
    fn octal_fields_are_zero_padded_to_their_width() {
        let mut field = Vec::new();
        push_octal(&mut field, "uid", 501, NARROW_FIELD).expect("501 fits in six digits");
        assert_eq!(field, b"000765");

        let mut wide = Vec::new();
        push_octal(&mut wide, "mtime", 8, WIDE_FIELD).expect("8 fits in eleven digits");
        assert_eq!(wide, b"00000000010");

        let header = build_header(
            "System/Library/CoreServices/boot.efi",
            9,
            CpioFileMeta {
                mode: MODE_TYPE_REGULAR | 0o644,
                uid: 501,
                gid: 20,
                mtime: 1_700_000_000,
            },
            1,
            4096,
        )
        .expect("the header fits");
        assert_eq!(&header[12..18], b"000011", "inode nine is octal 11");
        assert_eq!(&header[18..24], b"100644");
        assert_eq!(&header[24..30], b"000765");
        assert_eq!(&header[30..36], b"000024");
        assert_eq!(&header[36..42], b"000001");
        assert_eq!(&header[48..59], b"14524770400");
        assert_eq!(&header[59..65], b"000045", "37 name bytes is octal 45");
        assert_eq!(&header[65..76], b"00000010000", "4096 is octal 10000");
    }

    #[test]
    fn a_directory_entry_carries_no_body() {
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_directory("usr/standalone", meta(0o755, 42))
            .expect("the directory is written");
        let written = writer.into_inner();

        assert_eq!(
            written.len(),
            CPIO_HEADER_BYTES + "usr/standalone".len() + 1
        );
        assert_eq!(&written[18..24], b"040755");
        assert_eq!(&written[65..76], b"00000000000");
    }

    #[test]
    fn a_symlink_body_is_the_target_with_no_terminator() {
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_symlink("var", "private/var", meta(0o755, 42))
            .expect("the symlink is written");
        let written = writer.into_inner();

        assert_eq!(&written[18..24], b"120755");
        assert_eq!(&written[65..76], b"00000000013", "eleven bytes is octal 13");
        let body_at = CPIO_HEADER_BYTES + "var".len() + 1;
        assert_eq!(&written[body_at..], b"private/var");
        assert_eq!(written.len(), body_at + "private/var".len());
    }

    #[test]
    fn a_regular_file_body_is_the_bytes_verbatim() {
        let contents: Vec<u8> = (0u16..=511).map(|value| value as u8).collect();
        let mut source = contents.as_slice();
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_file(
                "Bootability/Manifest",
                contents.len() as u64,
                &mut source,
                meta(0o644, 42),
            )
            .expect("the file is written");

        let expected = CPIO_HEADER_BYTES as u64 + "Bootability/Manifest".len() as u64 + 1 + 512;
        assert_eq!(writer.bytes_written(), expected);
        assert_eq!(writer.entries_written(), 1);

        let written = writer.into_inner();
        assert_eq!(written.len() as u64, expected);
        let body_at = CPIO_HEADER_BYTES + "Bootability/Manifest".len() + 1;
        assert_eq!(&written[body_at..], contents.as_slice());
    }

    #[test]
    fn a_file_larger_than_the_copy_buffer_streams_through_intact() {
        let contents: Vec<u8> = (0..COPY_BUFFER_BYTES * 2 + 7)
            .map(|index| (index % 251) as u8)
            .collect();
        let mut source = contents.as_slice();
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_file(
                "kernelcache",
                contents.len() as u64,
                &mut source,
                meta(0o644, 7),
            )
            .expect("the file is written");
        writer.finish().expect("the trailer is written");

        let parsed = parse_archive(&writer.into_inner());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].body, contents);
    }

    #[test]
    fn the_trailer_is_the_fixed_final_entry() {
        let mut expected: Vec<u8> = Vec::new();
        expected.extend_from_slice(b"070707"); // magic
        expected.extend_from_slice(b"000000"); // dev
        expected.extend_from_slice(b"000000"); // ino
        expected.extend_from_slice(b"000000"); // mode
        expected.extend_from_slice(b"000000"); // uid
        expected.extend_from_slice(b"000000"); // gid
        expected.extend_from_slice(b"000001"); // nlink
        expected.extend_from_slice(b"000000"); // rdev
        expected.extend_from_slice(b"00000000000"); // mtime
        expected.extend_from_slice(b"000013"); // namesize, eleven bytes
        expected.extend_from_slice(b"00000000000"); // filesize
        expected.extend_from_slice(b"TRAILER!!!\0");
        assert_eq!(expected.len(), CPIO_HEADER_BYTES + 11);

        let mut writer = CpioWriter::new(Vec::new());
        writer.finish().expect("the trailer is written");
        assert_eq!(
            writer.entries_written(),
            0,
            "the trailer is not a member and must not be counted as one"
        );
        assert_eq!(writer.bytes_written(), expected.len() as u64);
        assert_eq!(writer.into_inner(), expected);
    }

    #[test]
    fn a_value_wider_than_its_field_is_refused_rather_than_truncated() {
        let too_large = 0o1_000_000;
        let error = build_header(
            "etc",
            1,
            CpioFileMeta {
                mode: MODE_TYPE_REGULAR | 0o644,
                uid: too_large,
                gid: 0,
                mtime: 0,
            },
            1,
            0,
        )
        .expect_err("a uid needing seven octal digits does not fit six");
        match error {
            CpioError::FieldTooLarge {
                field,
                value,
                width,
            } => {
                assert_eq!(field, "uid");
                assert_eq!(value, u64::from(too_large));
                assert_eq!(width, NARROW_FIELD);
            }
            other => panic!("expected a field width error, got {other}"),
        }

        let filesize_error = build_header(
            "etc",
            1,
            CpioFileMeta {
                mode: MODE_TYPE_REGULAR | 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            },
            1,
            0o100_000_000_000,
        )
        .expect_err("a filesize needing twelve octal digits does not fit eleven");
        assert!(matches!(
            filesize_error,
            CpioError::FieldTooLarge {
                field: "filesize",
                ..
            }
        ));
    }

    #[test]
    fn an_interior_nul_in_a_path_is_refused() {
        let mut writer = CpioWriter::new(Vec::new());
        let error = writer
            .write_directory("usr\0local", meta(0o755, 0))
            .expect_err("a path with a NUL cannot be written");
        match error {
            CpioError::NulInPath { path, offset } => {
                assert_eq!(path, "usr\0local");
                assert_eq!(offset, 3);
            }
            other => panic!("expected a NUL path error, got {other}"),
        }
        assert_eq!(writer.bytes_written(), 0, "nothing reached the stream");
        assert_eq!(writer.entries_written(), 0);
    }

    #[test]
    fn an_empty_path_is_refused() {
        let mut writer = CpioWriter::new(Vec::new());
        assert!(matches!(
            writer.write_directory("", meta(0o755, 0)),
            Err(CpioError::EmptyPath)
        ));
    }

    #[test]
    fn an_interior_nul_in_a_link_target_is_refused() {
        let mut writer = CpioWriter::new(Vec::new());
        let error = writer
            .write_symlink("var", "private\0var", meta(0o755, 0))
            .expect_err("a target with a NUL cannot be written");
        assert!(matches!(
            error,
            CpioError::NulInLinkTarget { offset: 7, .. }
        ));
        assert_eq!(writer.bytes_written(), 0);
    }

    #[test]
    fn mode_bits_outside_the_permission_mask_are_refused() {
        let mut writer = CpioWriter::new(Vec::new());
        let error = writer
            .write_directory("usr", meta(MODE_TYPE_REGULAR | 0o755, 0))
            .expect_err("a whole st_mode is not a permission set");
        match error {
            CpioError::ModeOutsidePermissionMask { path, mode } => {
                assert_eq!(path, "usr");
                assert_eq!(mode, MODE_TYPE_REGULAR | 0o755);
            }
            other => panic!("expected a permission mask error, got {other}"),
        }
    }

    #[test]
    fn a_short_source_is_refused_rather_than_left_desynchronised() {
        let contents = b"short".to_vec();
        let mut source = contents.as_slice();
        let mut writer = CpioWriter::new(Vec::new());
        let error = writer
            .write_file("Bootability/Payload", 64, &mut source, meta(0o644, 0))
            .expect_err("a source shorter than the declared length is refused");
        match error {
            CpioError::SourceTooShort {
                path,
                expected,
                copied,
            } => {
                assert_eq!(path, "Bootability/Payload");
                assert_eq!(expected, 64);
                assert_eq!(copied, 5);
            }
            other => panic!("expected a short source error, got {other}"),
        }
    }

    #[test]
    fn a_source_with_more_than_it_declared_is_refused() {
        let contents = b"sixteen bytes___and more".to_vec();
        let mut source = contents.as_slice();
        let mut writer = CpioWriter::new(Vec::new());
        let error = writer
            .write_file("Bootability/Payload", 16, &mut source, meta(0o644, 0))
            .expect_err("a source longer than the declared length is refused");
        assert!(matches!(
            error,
            CpioError::SourceTooLong { expected: 16, .. }
        ));
    }

    #[test]
    fn an_entry_whose_body_contradicts_its_type_is_refused() {
        let entry = CpioEntry {
            path: "var".to_string(),
            file_type: CpioFileType::Symlink,
            mode: 0o755,
            uid: 0,
            gid: 0,
            mtime: 0,
            body: CpioBody::Empty,
        };
        let mut writer = CpioWriter::new(Vec::new());
        assert!(matches!(
            writer.write_entry(&entry),
            Err(CpioError::BodyMismatch {
                file_type: CpioFileType::Symlink,
                ..
            })
        ));
    }

    #[test]
    fn inodes_are_distinct_so_no_member_reads_as_a_link_to_another() {
        let same = b"identical".to_vec();
        let mut writer = CpioWriter::new(Vec::new());
        writer
            .write_entry(&CpioEntry::regular_file(
                "one",
                same.clone(),
                0o644,
                0,
                0,
                1,
            ))
            .expect("the first copy is written");
        writer
            .write_entry(&CpioEntry::regular_file("two", same, 0o644, 0, 0, 1))
            .expect("the second copy is written");
        writer.finish().expect("the trailer is written");

        let parsed = parse_archive(&writer.into_inner());
        assert_eq!(parsed.len(), 2);
        assert_ne!(parsed[0].ino, parsed[1].ino);
        assert_eq!(parsed[0].nlink, 1);
        assert_eq!(parsed[1].nlink, 1);
    }

    #[test]
    fn an_archive_round_trips_through_a_parser() {
        let payload = b"<?xml version=\"1.0\"?>\n".to_vec();
        let entries = vec![
            CpioEntry::directory("Bootability", 0o755, 0, 0, 1_700_000_000),
            CpioEntry::regular_file(
                "Bootability/Bootability.dmg.trustcache",
                payload.clone(),
                0o644,
                501,
                20,
                1_700_000_001,
            ),
            CpioEntry::symlink(
                "Bootability/current",
                "Bootability/Bootability.dmg.trustcache",
                0o755,
                0,
                0,
                1_700_000_002,
            ),
        ];

        let mut writer = CpioWriter::new(Vec::new());
        for entry in &entries {
            writer.write_entry(entry).expect("the entry is written");
        }
        writer.finish().expect("the trailer is written");
        assert_eq!(writer.entries_written(), 3);
        let written = writer.into_inner();

        let parsed = parse_archive(&written);
        assert_eq!(parsed.len(), 3);

        assert_eq!(parsed[0].path, "Bootability");
        assert_eq!(parsed[0].mode, MODE_TYPE_DIRECTORY | 0o755);
        assert_eq!(parsed[0].mtime, 1_700_000_000);
        assert!(parsed[0].body.is_empty());

        assert_eq!(parsed[1].path, "Bootability/Bootability.dmg.trustcache");
        assert_eq!(parsed[1].mode, MODE_TYPE_REGULAR | 0o644);
        assert_eq!(parsed[1].uid, 501);
        assert_eq!(parsed[1].gid, 20);
        assert_eq!(parsed[1].body, payload);

        assert_eq!(parsed[2].path, "Bootability/current");
        assert_eq!(parsed[2].mode, MODE_TYPE_SYMLINK | 0o755);
        assert_eq!(
            parsed[2].body,
            b"Bootability/Bootability.dmg.trustcache".to_vec()
        );
    }

    #[test]
    fn the_declared_size_of_a_body_is_what_gets_written() {
        let entry = CpioEntry::symlink("var", "private/var", 0o755, 0, 0, 0);
        assert_eq!(entry.body.declared_size(), 11);

        let mut writer = CpioWriter::new(Vec::new());
        writer.write_entry(&entry).expect("the symlink is written");
        assert_eq!(
            writer.bytes_written(),
            CPIO_HEADER_BYTES as u64 + 4 + entry.body.declared_size()
        );
    }
}
