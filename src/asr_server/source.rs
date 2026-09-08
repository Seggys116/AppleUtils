use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub trait ImageSource {
    fn len(&self) -> u64;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
}

impl<T: ImageSource + ?Sized> ImageSource for &mut T {
    fn len(&self) -> u64 {
        (**self).len()
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        (**self).read_exact_at(offset, buf)
    }
}

fn check_range(len: u64, offset: u64, request: usize) -> io::Result<()> {
    let request = request as u64;
    let end = offset.checked_add(request).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("read of {request} bytes at offset {offset} overflows"),
        )
    })?;
    if end > len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("read of {request} bytes at offset {offset} runs past the {len}-byte source"),
        ));
    }
    Ok(())
}

pub struct FileImageSource {
    path: PathBuf,
    file: File,
    len: u64,
}

impl FileImageSource {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let len = file.metadata()?.len();
        Ok(Self { path, file, len })
    }

    pub fn open_prefix(path: impl AsRef<Path>, len: u64) -> io::Result<Self> {
        let source = Self::open(path)?;
        if len > source.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{}: requested prefix of {len} bytes exceeds the {} byte file",
                    source.path.display(),
                    source.len
                ),
            ));
        }
        Ok(Self { len, ..source })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ImageSource for FileImageSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len, offset, buf.len())?;
        if buf.is_empty() {
            return Ok(());
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }
}

pub struct MemoryImageSource {
    bytes: Vec<u8>,
}

impl MemoryImageSource {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl ImageSource for MemoryImageSource {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        check_range(self.len(), offset, buf.len())?;
        let start = offset as usize;
        buf.copy_from_slice(&self.bytes[start..start + buf.len()]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_source_reads_an_interior_range() {
        let mut source = MemoryImageSource::new((0..64u8).collect());
        let mut buf = [0u8; 8];
        source.read_exact_at(20, &mut buf).unwrap();
        assert_eq!(buf, [20, 21, 22, 23, 24, 25, 26, 27]);
    }

    #[test]
    fn memory_source_rejects_a_read_past_the_end() {
        let mut source = MemoryImageSource::new(vec![0u8; 16]);
        let mut buf = [0u8; 8];
        let err = source.read_exact_at(12, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn memory_source_rejects_an_offset_that_overflows() {
        let mut source = MemoryImageSource::new(vec![0u8; 16]);
        let mut buf = [0u8; 8];
        let err = source.read_exact_at(u64::MAX, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn file_source_reads_by_offset_without_holding_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.bin");
        let body: Vec<u8> = (0..4096u32).map(|index| (index % 253) as u8).collect();
        std::fs::write(&path, &body).unwrap();

        let mut source = FileImageSource::open(&path).unwrap();
        assert_eq!(source.len(), 4096);
        let mut buf = [0u8; 300];
        source.read_exact_at(1000, &mut buf).unwrap();
        assert_eq!(&buf[..], &body[1000..1300]);
    }

    #[test]
    fn file_source_prefix_shortens_the_served_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.bin");
        std::fs::write(&path, vec![7u8; 512]).unwrap();

        let mut source = FileImageSource::open_prefix(&path, 128).unwrap();
        assert_eq!(source.len(), 128);
        let mut buf = [0u8; 16];
        let err = source.read_exact_at(120, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        assert!(FileImageSource::open_prefix(&path, 1024).is_err());
    }
}
