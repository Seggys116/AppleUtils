use std::fmt;

use plist::{Dictionary, Integer, Value};

use super::deflate::{self, DeflateError};

pub const KEY_IMAGE_SIZE: &str = "Image Size";
pub const KEY_CHUNKS: &str = "Chunks";
pub const KEY_PARTITIONS: &str = "Partitions";
pub const KEY_FILESYSTEMS: &str = "Filesystems";

pub const CHUNK_HEADER_LEN: usize = 12;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageChunk {
    pub offset: u64,
    pub bytes: Vec<u8>,
}

impl ImageChunk {
    pub fn new(offset: u64, bytes: Vec<u8>) -> Self {
        Self { offset, bytes }
    }

    pub fn length(&self) -> u32 {
        self.bytes.len() as u32
    }

    pub fn encode_plain(&self) -> Result<Vec<u8>, MetadataError> {
        let length = u32::try_from(self.bytes.len())
            .map_err(|_| MetadataError::ChunkTooLong(self.bytes.len()))?;
        let mut out = Vec::with_capacity(CHUNK_HEADER_LEN + self.bytes.len());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(out)
    }

    // Must be a real zlib stream: unlike the top-level blob, a chunk element has no raw fallback.
    pub fn encode(&self) -> Result<Vec<u8>, MetadataError> {
        Ok(deflate::zlib_compress(&self.encode_plain()?))
    }

    pub fn decode(element: &[u8]) -> Result<Self, MetadataError> {
        Self::decode_plain(&deflate::zlib_decompress(element)?)
    }

    pub fn decode_plain(raw: &[u8]) -> Result<Self, MetadataError> {
        if raw.len() < CHUNK_HEADER_LEN {
            return Err(MetadataError::ShortChunk(raw.len()));
        }
        let offset = u64::from_be_bytes(raw[..8].try_into().expect("eight bytes"));
        let length = u32::from_be_bytes(raw[8..12].try_into().expect("four bytes")) as usize;
        let body = &raw[CHUNK_HEADER_LEN..];
        if body.len() != length {
            return Err(MetadataError::ChunkLengthMismatch {
                declared: length,
                present: body.len(),
            });
        }
        Ok(Self {
            offset,
            bytes: body.to_vec(),
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ImageMetadata {
    // asr reads `Image Size` and `Chunks` with no presence check; both are required.
    pub image_size: i64,
    pub chunks: Vec<ImageChunk>,
    pub partitions: Option<Value>,
    pub filesystems: Option<Value>,
}

impl ImageMetadata {
    pub fn for_image_size(image_size: i64) -> Self {
        Self {
            image_size,
            chunks: Vec::new(),
            partitions: None,
            filesystems: None,
        }
    }

    pub fn to_value(&self) -> Result<Value, MetadataError> {
        let mut dict = Dictionary::new();
        dict.insert(
            KEY_IMAGE_SIZE.to_string(),
            Value::Integer(Integer::from(self.image_size)),
        );
        let mut chunks = Vec::with_capacity(self.chunks.len());
        for chunk in &self.chunks {
            chunks.push(Value::Data(chunk.encode()?));
        }
        dict.insert(KEY_CHUNKS.to_string(), Value::Array(chunks));
        if let Some(partitions) = &self.partitions {
            dict.insert(KEY_PARTITIONS.to_string(), partitions.clone());
        }
        if let Some(filesystems) = &self.filesystems {
            dict.insert(KEY_FILESYSTEMS.to_string(), filesystems.clone());
        }
        Ok(Value::Dictionary(dict))
    }

    pub fn to_blob(&self) -> Result<Vec<u8>, MetadataError> {
        let value = self.to_value()?;
        let mut bytes = Vec::new();
        value.to_writer_xml(&mut bytes)?;
        Ok(bytes)
    }

    pub fn to_gzip_blob(&self) -> Result<Vec<u8>, MetadataError> {
        Ok(deflate::gzip_compress(&self.to_blob()?))
    }

    pub fn from_value(value: &Value) -> Result<Self, MetadataError> {
        let dict = value
            .as_dictionary()
            .ok_or(MetadataError::Malformed("metadata is not a dictionary"))?;
        let image_size = dict
            .get(KEY_IMAGE_SIZE)
            .and_then(Value::as_signed_integer)
            .ok_or(MetadataError::MissingKey(KEY_IMAGE_SIZE))?;
        let chunk_values = dict
            .get(KEY_CHUNKS)
            .and_then(Value::as_array)
            .ok_or(MetadataError::MissingKey(KEY_CHUNKS))?;
        let mut chunks = Vec::with_capacity(chunk_values.len());
        for entry in chunk_values {
            let raw = entry
                .as_data()
                .ok_or(MetadataError::Malformed("a Chunks element is not data"))?;
            chunks.push(ImageChunk::decode(raw)?);
        }
        Ok(Self {
            image_size,
            chunks,
            partitions: dict.get(KEY_PARTITIONS).cloned(),
            filesystems: dict.get(KEY_FILESYSTEMS).cloned(),
        })
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, MetadataError> {
        let inflated = deflate::gzip_decompress(blob)
            .or_else(|_| deflate::zlib_decompress(blob))
            .unwrap_or_else(|_| blob.to_vec());
        let value = Value::from_reader_xml(std::io::Cursor::new(inflated))?;
        Self::from_value(&value)
    }
}

#[derive(Debug)]
pub enum MetadataError {
    Plist(plist::Error),
    Deflate(DeflateError),
    ChunkTooLong(usize),
    ShortChunk(usize),
    ChunkLengthMismatch { declared: usize, present: usize },
    MissingKey(&'static str),
    Malformed(&'static str),
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plist(err) => write!(f, "{err}"),
            Self::Deflate(err) => write!(f, "{err}"),
            Self::ChunkTooLong(len) => {
                write!(f, "chunk of {len} bytes exceeds the 32-bit length field")
            }
            Self::ShortChunk(len) => write!(
                f,
                "encoded chunk of {len} bytes is shorter than its {CHUNK_HEADER_LEN}-byte header"
            ),
            Self::ChunkLengthMismatch { declared, present } => write!(
                f,
                "encoded chunk declares {declared} bytes but carries {present}"
            ),
            Self::MissingKey(key) => write!(f, "metadata has no {key} key"),
            Self::Malformed(reason) => write!(f, "malformed metadata: {reason}"),
        }
    }
}

impl std::error::Error for MetadataError {}

impl From<plist::Error> for MetadataError {
    fn from(err: plist::Error) -> Self {
        Self::Plist(err)
    }
}

impl From<DeflateError> for MetadataError {
    fn from(err: DeflateError) -> Self {
        Self::Deflate(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_encodes_as_big_endian_offset_then_length_then_bytes() {
        let chunk = ImageChunk::new(0x0102_0304_0506_0708, vec![0xaa, 0xbb, 0xcc]);
        let plain = chunk.encode_plain().unwrap();
        assert_eq!(
            plain,
            vec![
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // offset, big endian
                0x00, 0x00, 0x00, 0x03, // length, big endian
                0xaa, 0xbb, 0xcc, // literal bytes
            ]
        );
        assert_eq!(chunk.length(), 3);
        assert_eq!(ImageChunk::decode_plain(&plain).unwrap(), chunk);
    }

    #[test]
    fn a_chunk_array_element_is_the_whole_descriptor_inside_a_zlib_stream() {
        let chunk = ImageChunk::new(0x2000, vec![0x11, 0x22, 0x33, 0x44]);
        let element = chunk.encode().unwrap();
        assert_eq!(&element[..2], &[0x78, 0x01]);
        assert_eq!(
            deflate::zlib_decompress(&element).unwrap(),
            chunk.encode_plain().unwrap()
        );
        assert_eq!(ImageChunk::decode(&element).unwrap(), chunk);
    }

    #[test]
    fn an_empty_chunk_encodes_to_the_bare_header() {
        let chunk = ImageChunk::new(0, Vec::new());
        let plain = chunk.encode_plain().unwrap();
        assert_eq!(plain.len(), CHUNK_HEADER_LEN);
        assert_eq!(ImageChunk::decode(&chunk.encode().unwrap()).unwrap(), chunk);
    }

    #[test]
    fn a_chunk_whose_length_field_disagrees_with_its_body_is_rejected() {
        let mut plain = ImageChunk::new(4, vec![1, 2, 3, 4]).encode_plain().unwrap();
        plain[11] = 9;
        assert!(matches!(
            ImageChunk::decode_plain(&plain),
            Err(MetadataError::ChunkLengthMismatch {
                declared: 9,
                present: 4
            })
        ));
        assert!(matches!(
            ImageChunk::decode_plain(&plain[..6]),
            Err(MetadataError::ShortChunk(6))
        ));
    }

    #[test]
    fn a_metadata_blob_round_trips_through_its_xml_form() {
        let metadata = ImageMetadata {
            image_size: 13_071_548_416,
            chunks: vec![
                ImageChunk::new(0, vec![0x4e, 0x58, 0x53, 0x42]),
                ImageChunk::new(0x2000, vec![0xff; 40]),
            ],
            partitions: None,
            filesystems: None,
        };
        let blob = metadata.to_blob().unwrap();
        assert!(blob.starts_with(b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(blob.ends_with(b"</plist>"));
        assert_eq!(ImageMetadata::from_blob(&blob).unwrap(), metadata);
    }

    #[test]
    fn a_metadata_blob_round_trips_through_its_gzip_form() {
        let metadata = ImageMetadata {
            image_size: 7_096_762_368,
            chunks: vec![ImageChunk::new(0x20, b"NXSB".to_vec())],
            partitions: None,
            filesystems: None,
        };
        let blob = metadata.to_gzip_blob().unwrap();
        assert_eq!(&blob[..3], &[0x1f, 0x8b, 0x08]);
        assert_eq!(
            deflate::gzip_decompress(&blob).unwrap(),
            metadata.to_blob().unwrap()
        );
        assert_eq!(ImageMetadata::from_blob(&blob).unwrap(), metadata);
    }

    #[test]
    fn optional_keys_are_omitted_when_absent_and_preserved_when_present() {
        let bare = ImageMetadata::for_image_size(1024);
        let blob = bare.to_blob().unwrap();
        let text = String::from_utf8(blob).unwrap();
        assert!(!text.contains(KEY_PARTITIONS));
        assert!(!text.contains(KEY_FILESYSTEMS));
        assert!(text.contains(KEY_IMAGE_SIZE));
        assert!(text.contains(KEY_CHUNKS));

        let mut described = bare.clone();
        described.partitions = Some(Value::Array(vec![Value::String("disk0s1".to_string())]));
        described.filesystems = Some(Value::Array(vec![Value::String("apfs".to_string())]));
        let blob = described.to_blob().unwrap();
        assert_eq!(ImageMetadata::from_blob(&blob).unwrap(), described);
    }

    #[test]
    fn metadata_missing_a_required_key_is_rejected() {
        let mut dict = Dictionary::new();
        dict.insert(KEY_CHUNKS.to_string(), Value::Array(Vec::new()));
        assert!(matches!(
            ImageMetadata::from_value(&Value::Dictionary(dict)),
            Err(MetadataError::MissingKey(KEY_IMAGE_SIZE))
        ));

        let mut dict = Dictionary::new();
        dict.insert(KEY_IMAGE_SIZE.to_string(), Value::Integer(Integer::from(1)));
        assert!(matches!(
            ImageMetadata::from_value(&Value::Dictionary(dict)),
            Err(MetadataError::MissingKey(KEY_CHUNKS))
        ));
    }
}
