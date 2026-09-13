use crate::apfs_verify::{BlockSource, VerifyError};
use crate::asahi_ops::{ImageIo, OpsError};

#[derive(Debug)]
pub enum DiscError {
    Io(String),
    OutOfRange { paddr: u64 },
    BlockLength { expected: u32, actual: usize },
}

impl std::fmt::Display for DiscError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::OutOfRange { paddr } => write!(f, "block {paddr} is outside the container"),
            Self::BlockLength { expected, actual } => write!(
                f,
                "buffer of {actual} bytes does not match block size {expected}"
            ),
        }
    }
}

impl std::error::Error for DiscError {}

impl From<OpsError> for DiscError {
    fn from(error: OpsError) -> Self {
        Self::Io(error.to_string())
    }
}

/// Block-addressed view of one APFS container inside an [`ImageIo`] backend.
pub struct RepairSession<'a> {
    disc: &'a mut dyn ImageIo,
    container_offset: u64,
    block_size: u32,
    block_count: u64,
}

impl<'a> RepairSession<'a> {
    pub fn new(
        disc: &'a mut dyn ImageIo,
        container_offset: u64,
        block_size: u32,
        block_count: u64,
    ) -> Self {
        Self {
            disc,
            container_offset,
            block_size,
            block_count,
        }
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    fn absolute(&self, paddr: u64) -> Result<u64, DiscError> {
        if paddr >= self.block_count {
            return Err(DiscError::OutOfRange { paddr });
        }
        self.container_offset
            .checked_add(paddr.saturating_mul(u64::from(self.block_size)))
            .ok_or(DiscError::OutOfRange { paddr })
    }

    pub fn read_block(&mut self, paddr: u64, into: &mut [u8]) -> Result<(), DiscError> {
        if into.len() != self.block_size as usize {
            return Err(DiscError::BlockLength {
                expected: self.block_size,
                actual: into.len(),
            });
        }
        let at = self.absolute(paddr)?;
        self.disc.read_at(at, into)?;
        Ok(())
    }

    pub fn write_block(&mut self, paddr: u64, from: &[u8]) -> Result<(), DiscError> {
        if from.len() != self.block_size as usize {
            return Err(DiscError::BlockLength {
                expected: self.block_size,
                actual: from.len(),
            });
        }
        let at = self.absolute(paddr)?;
        self.disc.write_at(at, from)?;
        Ok(())
    }
}

impl BlockSource for RepairSession<'_> {
    fn read_block(&mut self, index: u64, into: &mut [u8]) -> Result<(), VerifyError> {
        RepairSession::read_block(self, index, into)
            .map_err(|_| VerifyError::BlockOutOfRange { index })
    }
}

#[cfg(test)]
pub(crate) struct MemoryImage {
    pub bytes: Vec<u8>,
}

#[cfg(test)]
impl ImageIo for MemoryImage {
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<(), OpsError> {
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        if start >= self.bytes.len() {
            buf.fill(0);
            return Ok(());
        }
        let copy = (self.bytes.len() - start).min(buf.len());
        buf[..copy].copy_from_slice(&self.bytes[start..start + copy]);
        buf[copy..].fill(0);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<(), OpsError> {
        let start =
            usize::try_from(offset).map_err(|_| OpsError::Message("offset overflow".into()))?;
        let end = start
            .checked_add(data.len())
            .ok_or_else(|| OpsError::Message("write overflow".into()))?;
        if end > self.bytes.len() {
            self.bytes.resize(end, 0);
        }
        self.bytes[start..end].copy_from_slice(data);
        Ok(())
    }
}
