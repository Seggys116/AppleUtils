use crate::embedded_panic_crc32;

const MAX_STORED_BLOCK: usize = 0xffff;

const ZLIB_CMF: u8 = 0x78;

const ZLIB_FLG: u8 = 0x01;

pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / MAX_STORED_BLOCK * 5 + 5);
    if data.is_empty() {
        push_stored_block(&mut out, &[], true);
        return out;
    }
    let mut chunks = data.chunks(MAX_STORED_BLOCK).peekable();
    while let Some(chunk) = chunks.next() {
        push_stored_block(&mut out, chunk, chunks.peek().is_none());
    }
    out
}

fn push_stored_block(out: &mut Vec<u8>, block: &[u8], final_block: bool) {
    out.push(u8::from(final_block));
    let len = block.len() as u16;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&(!len).to_le_bytes());
    out.extend_from_slice(block);
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.push(ZLIB_CMF);
    out.push(ZLIB_FLG);
    out.extend_from_slice(&deflate_stored(data));
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

pub fn gzip_compress(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 32);
    out.extend_from_slice(&[
        0x1f, 0x8b, // magic
        0x08, // compression method: DEFLATE
        0x00, // flags: no name, no comment, no extra field, no header CRC
        0x00, 0x00, 0x00, 0x00, // modification time: not set
        0x00, // extra flags
        0xff, // operating system: unknown
    ]);
    out.extend_from_slice(&deflate_stored(data));
    out.extend_from_slice(&embedded_panic_crc32(data).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out
}

pub fn inflate_stored(mut stream: &[u8]) -> Result<Vec<u8>, DeflateError> {
    let mut out = Vec::new();
    loop {
        let header = *stream.first().ok_or(DeflateError::Truncated)?;
        let block_type = (header >> 1) & 0b11;
        if block_type != 0 {
            return Err(DeflateError::UnsupportedBlockType(block_type));
        }
        let final_block = header & 1 == 1;
        let len_bytes = stream.get(1..5).ok_or(DeflateError::Truncated)?;
        let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]);
        let nlen = u16::from_le_bytes([len_bytes[2], len_bytes[3]]);
        if nlen != !len {
            return Err(DeflateError::StoredLengthMismatch { len, nlen });
        }
        let end = 5 + len as usize;
        out.extend_from_slice(stream.get(5..end).ok_or(DeflateError::Truncated)?);
        stream = &stream[end..];
        if final_block {
            break;
        }
    }
    if stream.is_empty() {
        Ok(out)
    } else {
        Err(DeflateError::TrailingBytes(stream.len()))
    }
}

pub fn zlib_decompress(stream: &[u8]) -> Result<Vec<u8>, DeflateError> {
    if stream.len() < 6 {
        return Err(DeflateError::Truncated);
    }
    let header = u16::from_be_bytes([stream[0], stream[1]]);
    if stream[0] & 0x0f != 8 || !header.is_multiple_of(31) {
        return Err(DeflateError::NotZlib);
    }
    if stream[1] & 0x20 != 0 {
        return Err(DeflateError::PresetDictionary);
    }
    let body = &stream[2..stream.len() - 4];
    let expected = u32::from_be_bytes(stream[stream.len() - 4..].try_into().expect("four bytes"));
    let out = inflate_stored(body)?;
    let actual = adler32(&out);
    if actual != expected {
        return Err(DeflateError::ChecksumMismatch { expected, actual });
    }
    Ok(out)
}

pub fn gzip_decompress(stream: &[u8]) -> Result<Vec<u8>, DeflateError> {
    if stream.len() < 18 {
        return Err(DeflateError::Truncated);
    }
    if stream[0] != 0x1f || stream[1] != 0x8b || stream[2] != 0x08 {
        return Err(DeflateError::NotGzip);
    }
    if stream[3] != 0 {
        return Err(DeflateError::UnsupportedGzipFlags(stream[3]));
    }
    let body = &stream[10..stream.len() - 8];
    let out = inflate_stored(body)?;
    let expected = u32::from_le_bytes(
        stream[stream.len() - 8..stream.len() - 4]
            .try_into()
            .expect("four bytes"),
    );
    let actual = embedded_panic_crc32(&out);
    if actual != expected {
        return Err(DeflateError::ChecksumMismatch { expected, actual });
    }
    let declared = u32::from_le_bytes(stream[stream.len() - 4..].try_into().expect("four bytes"));
    if declared != out.len() as u32 {
        return Err(DeflateError::LengthMismatch {
            declared,
            actual: out.len(),
        });
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeflateError {
    Truncated,
    TrailingBytes(usize),
    UnsupportedBlockType(u8),
    StoredLengthMismatch { len: u16, nlen: u16 },
    NotZlib,
    NotGzip,
    PresetDictionary,
    UnsupportedGzipFlags(u8),
    ChecksumMismatch { expected: u32, actual: u32 },
    LengthMismatch { declared: u32, actual: usize },
}

impl std::fmt::Display for DeflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => f.write_str("stream ends inside a block"),
            Self::TrailingBytes(len) => write!(f, "{len} bytes follow the final block"),
            Self::UnsupportedBlockType(kind) => {
                write!(f, "DEFLATE block type {kind} is not a stored block")
            }
            Self::StoredLengthMismatch { len, nlen } => {
                write!(f, "stored block length {len} does not complement {nlen}")
            }
            Self::NotZlib => f.write_str("not a zlib stream"),
            Self::NotGzip => f.write_str("not a gzip stream"),
            Self::PresetDictionary => f.write_str("zlib preset dictionaries are not supported"),
            Self::UnsupportedGzipFlags(flags) => write!(f, "unsupported gzip flags {flags:#04x}"),
            Self::ChecksumMismatch { expected, actual } => {
                write!(f, "checksum {actual:#010x} does not match {expected:#010x}")
            }
            Self::LengthMismatch { declared, actual } => {
                write!(f, "gzip declares {declared} bytes but decoded {actual}")
            }
        }
    }
}

impl std::error::Error for DeflateError {}

pub fn adler32(data: &[u8]) -> u32 {
    const MODULUS: u32 = 65521;
    let mut low = 1u32;
    let mut high = 0u32;
    for run in data.chunks(5552) {
        for byte in run {
            low += u32::from(*byte);
            high += low;
        }
        low %= MODULUS;
        high %= MODULUS;
    }
    (high << 16) | low
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_the_rfc_1950_worked_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"a"), 0x0062_0062);
        assert_eq!(adler32(b"abc"), 0x024d_0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn a_stored_deflate_stream_round_trips_through_an_independent_reader() {
        for len in [0usize, 1, 5, 4096, MAX_STORED_BLOCK, MAX_STORED_BLOCK + 1] {
            let data: Vec<u8> = (0..len).map(|index| (index % 251) as u8).collect();
            let stream = deflate_stored(&data);
            assert_eq!(inflate_stored(&stream).unwrap(), data);
        }
    }

    #[test]
    fn a_long_body_is_split_into_whole_stored_blocks_with_one_final_flag() {
        let data = vec![0x5au8; MAX_STORED_BLOCK * 2 + 7];
        let stream = deflate_stored(&data);
        assert_eq!(stream[0], 0);
        assert_eq!(
            u16::from_le_bytes(stream[1..3].try_into().unwrap()),
            MAX_STORED_BLOCK as u16
        );
        let second = 5 + MAX_STORED_BLOCK;
        assert_eq!(stream[second], 0);
        let third = second + 5 + MAX_STORED_BLOCK;
        assert_eq!(stream[third], 1);
        assert_eq!(
            u16::from_le_bytes(stream[third + 1..third + 3].try_into().unwrap()),
            7
        );
        assert_eq!(inflate_stored(&stream).unwrap(), data);
    }

    #[test]
    fn a_zlib_stream_carries_the_expected_header_and_adler_trailer() {
        let data = b"metadata chunk body".to_vec();
        let stream = zlib_compress(&data);
        assert_eq!(&stream[..2], &[0x78, 0x01]);
        assert_eq!(u16::from_be_bytes([stream[0], stream[1]]) % 31, 0);
        let trailer = &stream[stream.len() - 4..];
        assert_eq!(
            u32::from_be_bytes(trailer.try_into().unwrap()),
            adler32(&data)
        );
        assert_eq!(inflate_stored(&stream[2..stream.len() - 4]).unwrap(), data);
        assert_eq!(zlib_decompress(&stream).unwrap(), data);
    }

    #[test]
    fn a_gzip_stream_carries_the_expected_header_crc_and_length() {
        let data = b"top level metadata blob".to_vec();
        let stream = gzip_compress(&data);
        assert_eq!(&stream[..4], &[0x1f, 0x8b, 0x08, 0x00]);
        assert_eq!(stream[9], 0xff);
        let crc = u32::from_le_bytes(
            stream[stream.len() - 8..stream.len() - 4]
                .try_into()
                .unwrap(),
        );
        let isize_field = u32::from_le_bytes(stream[stream.len() - 4..].try_into().unwrap());
        assert_eq!(crc, embedded_panic_crc32(&data));
        assert_eq!(isize_field, data.len() as u32);
        assert_eq!(inflate_stored(&stream[10..stream.len() - 8]).unwrap(), data);
        assert_eq!(gzip_decompress(&stream).unwrap(), data);
    }

    #[test]
    fn empty_input_still_produces_a_complete_stream() {
        assert_eq!(deflate_stored(b""), vec![1, 0, 0, 0xff, 0xff]);
        assert_eq!(
            inflate_stored(&deflate_stored(b"")).unwrap(),
            Vec::<u8>::new()
        );
        assert_eq!(zlib_compress(b"").len(), 2 + 5 + 4);
        assert_eq!(gzip_compress(b"").len(), 10 + 5 + 8);
    }
}
