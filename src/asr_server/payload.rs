use std::io::{self, Write};

use super::digest::{ChecksumType, StreamDigestKind};
use super::producer::AsrPhase;
use super::source::ImageSource;

pub const DEFAULT_BLOCK_LEN: usize = 0x10_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayloadPlan {
    pub size: u64,
    pub checksum_chunk_size: u64,
    pub checksum_type: ChecksumType,
    pub stream_digest: StreamDigestKind,
}

impl PayloadPlan {
    pub fn block_len(&self) -> usize {
        if self.checksum_chunk_size == 0 {
            DEFAULT_BLOCK_LEN
        } else {
            usize::try_from(self.checksum_chunk_size).unwrap_or(usize::MAX)
        }
    }

    pub fn digest_len(&self) -> usize {
        if self.checksum_chunk_size == 0 {
            0
        } else {
            self.checksum_type.digest_len()
        }
    }

    pub fn block_count(&self) -> u64 {
        let block_len = self.block_len() as u64;
        self.size.div_ceil(block_len)
    }

    pub fn wire_len(&self) -> u64 {
        self.size + self.block_count() * self.digest_len() as u64
    }

    pub fn block_data_len_at(&self, offset: u64) -> Option<usize> {
        if offset >= self.size {
            return None;
        }
        let remaining = self.size - offset;
        Some(usize::try_from(remaining.min(self.block_len() as u64)).unwrap_or(usize::MAX))
    }
}

pub trait PayloadObserver {
    fn block_sent(&mut self, offset: u64, data_len: usize);

    fn should_stop(&mut self) -> bool {
        false
    }

    fn image_matched(
        &mut self,
        _data_type: &str,
        _port: u16,
        _image: &std::path::Path,
        _origin: &str,
        _payload_size: u64,
    ) {
    }

    // Called several times per block on the serving thread: an implementation must do no IO and take no lock.
    fn entered_phase(&mut self, _phase: AsrPhase, _offset: u64) {}

    fn serving_port(&mut self, _port: u16, _payload_size: u64) {}
}

impl PayloadObserver for () {
    fn block_sent(&mut self, _offset: u64, _data_len: usize) {}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadSummary {
    pub data_bytes: u64,
    pub wire_bytes: u64,
    pub blocks: u64,
    pub stream_digest: Vec<u8>,
    pub stopped_early: bool,
}

// The stream ends on byte count alone: nothing may follow the last block.
pub fn stream_payload<S, W, O>(
    source: &mut S,
    out: &mut W,
    plan: &PayloadPlan,
    observer: &mut O,
) -> io::Result<PayloadSummary>
where
    S: ImageSource + ?Sized,
    W: Write + ?Sized,
    O: PayloadObserver + ?Sized,
{
    if plan.size > source.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "payload of {} bytes exceeds the {} byte source",
                plan.size,
                source.len()
            ),
        ));
    }

    let block_len = plan.block_len();
    if block_len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "payload block length is zero",
        ));
    }
    let digest_len = plan.digest_len();

    let mut buffer = vec![0u8; block_len + digest_len];
    let mut stream_hasher = plan.stream_digest.hasher();
    let mut offset = 0u64;
    let mut blocks = 0u64;
    let mut wire_bytes = 0u64;
    let mut stopped_early = false;

    while let Some(data_len) = plan.block_data_len_at(offset) {
        let frame_len = data_len + digest_len;
        observer.entered_phase(AsrPhase::ReadingImage, offset);
        source.read_exact_at(offset, &mut buffer[..data_len])?;

        observer.entered_phase(AsrPhase::DigestingBlock, offset);
        stream_hasher.update(&buffer[..data_len]);
        if digest_len != 0 {
            let block_digest = plan.checksum_type.digest(&buffer[..data_len]);
            debug_assert_eq!(block_digest.len(), digest_len);
            buffer[data_len..frame_len].copy_from_slice(&block_digest);
        }

        observer.entered_phase(AsrPhase::WritingPayload, offset);
        out.write_all(&buffer[..frame_len])?;
        wire_bytes += frame_len as u64;

        observer.entered_phase(AsrPhase::Reporting, offset);
        observer.block_sent(offset, data_len);
        offset += data_len as u64;
        blocks += 1;

        if observer.should_stop() && offset < plan.size {
            stopped_early = true;
            break;
        }
    }

    observer.entered_phase(AsrPhase::FlushingPayload, offset);
    out.flush()?;

    Ok(PayloadSummary {
        data_bytes: offset,
        wire_bytes,
        blocks,
        stream_digest: stream_hasher.finish(),
        stopped_early,
    })
}

#[cfg(test)]
mod tests {
    use super::super::source::MemoryImageSource;
    use super::*;

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn plan(size: u64, chunk: u64, checksum: ChecksumType) -> PayloadPlan {
        PayloadPlan {
            size,
            checksum_chunk_size: chunk,
            checksum_type: checksum,
            stream_digest: StreamDigestKind::Sha384,
        }
    }

    #[test]
    fn each_block_is_data_then_digest_with_the_digest_last() {
        let image = body(4096);
        let plan = plan(4096, 1024, ChecksumType::Sha256);
        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();

        assert_eq!(summary.blocks, 4);
        assert_eq!(summary.data_bytes, 4096);
        assert_eq!(summary.wire_bytes, 4096 + 4 * 32);
        assert_eq!(wire.len() as u64, plan.wire_len());

        let mut cursor = 0usize;
        for index in 0..4usize {
            let data = &wire[cursor..cursor + 1024];
            cursor += 1024;
            let digest = &wire[cursor..cursor + 32];
            cursor += 32;
            assert_eq!(data, &image[index * 1024..(index + 1) * 1024]);
            assert_eq!(digest, &ChecksumType::Sha256.digest(data)[..]);
        }
        assert_eq!(cursor, wire.len());
    }

    #[test]
    fn a_sha1_checksum_type_appends_twenty_bytes_per_block() {
        let image = body(300);
        let plan = plan(300, 100, ChecksumType::Sha1);
        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();

        assert_eq!(wire.len(), 300 + 3 * 20);
        let mut cursor = 0usize;
        for index in 0..3usize {
            let data = &wire[cursor..cursor + 100];
            cursor += 100;
            let digest = &wire[cursor..cursor + 20];
            cursor += 20;
            assert_eq!(data, &image[index * 100..(index + 1) * 100]);
            assert_eq!(digest, &ChecksumType::Sha1.digest(data)[..]);
        }
    }

    #[test]
    fn the_final_block_is_short_and_its_digest_covers_only_the_short_block() {
        let image = body(2500);
        let plan = plan(2500, 1024, ChecksumType::Sha256);
        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();

        assert_eq!(summary.blocks, 3);
        assert_eq!(plan.block_data_len_at(0), Some(1024));
        assert_eq!(plan.block_data_len_at(2048), Some(452));
        assert_eq!(plan.block_data_len_at(2500), None);
        assert_eq!(wire.len(), 2500 + 3 * 32);

        let tail_data = &wire[2 * (1024 + 32)..2 * (1024 + 32) + 452];
        let tail_digest = &wire[2 * (1024 + 32) + 452..];
        assert_eq!(tail_data, &image[2048..2500]);
        assert_eq!(tail_digest, &ChecksumType::Sha256.digest(tail_data)[..]);
        assert_eq!(tail_digest.len(), 32);
    }

    #[test]
    fn a_zero_checksum_chunk_size_streams_plain_bytes_in_one_mib_reads() {
        let size = DEFAULT_BLOCK_LEN + 4096;
        let image = body(size);
        let plan = plan(size as u64, 0, ChecksumType::Sha256);
        assert_eq!(plan.block_len(), DEFAULT_BLOCK_LEN);
        assert_eq!(plan.digest_len(), 0);
        assert_eq!(plan.block_count(), 2);
        assert_eq!(plan.wire_len(), size as u64);

        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();

        assert_eq!(wire, image);
        assert_eq!(summary.blocks, 2);
        assert_eq!(summary.wire_bytes, size as u64);
    }

    #[test]
    fn the_stream_digest_covers_the_data_bytes_and_not_the_block_digests() {
        let image = body(3000);
        let with_digests = plan(3000, 512, ChecksumType::Sha256);
        let without_digests = plan(3000, 0, ChecksumType::Sha256);

        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let framed = stream_payload(&mut source, &mut wire, &with_digests, &mut ()).unwrap();
        assert!(wire.len() > image.len());

        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let plain = stream_payload(&mut source, &mut wire, &without_digests, &mut ()).unwrap();

        assert_eq!(framed.stream_digest, plain.stream_digest);
        assert_eq!(
            framed.stream_digest,
            StreamDigestKind::Sha384.digest(&image)
        );
        assert_eq!(framed.stream_digest.len(), 48);
    }

    #[test]
    fn a_sha1_stream_digest_is_selected_by_the_expected_hash_length() {
        let image = body(600);
        let mut plan = plan(600, 256, ChecksumType::Sha1);
        plan.stream_digest = StreamDigestKind::for_expected_hash_len(20);
        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();
        assert_eq!(summary.stream_digest, StreamDigestKind::Sha1.digest(&image));
        assert_eq!(summary.stream_digest.len(), 20);
    }

    #[test]
    fn a_payload_size_shorter_than_the_source_streams_only_the_prefix() {
        let image = body(4096);
        let plan = plan(1000, 256, ChecksumType::Sha256);
        let mut source = MemoryImageSource::new(image.clone());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();

        assert_eq!(summary.data_bytes, 1000);
        assert_eq!(summary.blocks, 4);
        assert_eq!(
            summary.stream_digest,
            StreamDigestKind::Sha384.digest(&image[..1000])
        );
    }

    #[test]
    fn a_payload_size_longer_than_the_source_is_refused_before_any_byte_moves() {
        let plan = plan(4096, 1024, ChecksumType::Sha256);
        let mut source = MemoryImageSource::new(body(100));
        let mut wire = Vec::new();
        let err = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(wire.is_empty());
    }

    #[test]
    fn an_empty_payload_writes_nothing_at_all() {
        let plan = plan(0, 1024, ChecksumType::Sha256);
        assert_eq!(plan.block_count(), 0);
        assert_eq!(plan.wire_len(), 0);
        let mut source = MemoryImageSource::new(Vec::new());
        let mut wire = Vec::new();
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut ()).unwrap();
        assert!(wire.is_empty());
        assert_eq!(summary.blocks, 0);
        assert_eq!(summary.stream_digest, StreamDigestKind::Sha384.digest(b""));
    }

    #[test]
    fn an_observer_sees_every_block_offset_and_can_stop_the_stream() {
        struct Recorder {
            offsets: Vec<(u64, usize)>,
            stop_after: usize,
        }
        impl PayloadObserver for Recorder {
            fn block_sent(&mut self, offset: u64, data_len: usize) {
                self.offsets.push((offset, data_len));
            }
            fn should_stop(&mut self) -> bool {
                self.offsets.len() >= self.stop_after
            }
        }

        let plan = plan(2500, 1000, ChecksumType::Sha256);
        let mut source = MemoryImageSource::new(body(2500));
        let mut wire = Vec::new();
        let mut recorder = Recorder {
            offsets: Vec::new(),
            stop_after: 2,
        };
        let summary = stream_payload(&mut source, &mut wire, &plan, &mut recorder).unwrap();

        assert_eq!(recorder.offsets, vec![(0, 1000), (1000, 1000)]);
        assert!(summary.stopped_early);
        assert_eq!(summary.data_bytes, 2000);
        assert!(summary.wire_bytes < plan.wire_len());
    }
}
