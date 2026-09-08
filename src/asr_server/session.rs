use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};

use plist::{Dictionary, Integer, Value};

use super::codec::{self, Command, PlistReader, Request};
use super::deflate;
use super::digest::{ChecksumType, StreamDigestKind};
use super::message::{
    InitiateRequest, InitiateResponse, KEY_OOB_CHUNK, KEY_OOB_ERROR, KEY_OOB_LENGTH,
    KEY_OOB_OFFSET, KEY_OOB_RANGES, StreamDescriptor,
};
use super::metadata::{ImageMetadata, MetadataError};
use super::payload::{PayloadObserver, PayloadPlan, PayloadSummary, stream_payload};
use super::producer::AsrPhase;
use super::source::ImageSource;

const OOB_READ_ERROR: i64 = 5;

pub trait AsrTransport: Read + Write {
    fn shutdown_write(&mut self) -> io::Result<()>;
}

impl AsrTransport for TcpStream {
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetadataBlob {
    bytes: Vec<u8>,
    checksum: Option<Vec<u8>>,
}

impl MetadataBlob {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            checksum: None,
        }
    }

    pub fn plain(metadata: &ImageMetadata) -> Result<Self, MetadataError> {
        Ok(Self::from_bytes(metadata.to_blob()?))
    }

    pub fn gzip(metadata: &ImageMetadata) -> Result<Self, MetadataError> {
        Ok(Self::from_bytes(metadata.to_gzip_blob()?))
    }

    pub fn with_checksum(mut self) -> Self {
        self.checksum = Some(ChecksumType::Sha1.digest(&self.bytes));
        self
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn descriptor(&self) -> StreamDescriptor {
        let descriptor = StreamDescriptor::on_control_connection(self.bytes.len() as i64);
        match &self.checksum {
            Some(checksum) => descriptor.with_checksum(checksum.clone()),
            None => descriptor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AsrServerConfig {
    pub payload_size: Option<u64>,
    pub stream_id: i64,
    pub image_name: Option<String>,
    pub uuid: Option<String>,
    pub checksum_chunk_size: u64,
    pub checksum_type: ChecksumType,
    pub metadata: Option<MetadataBlob>,
    pub expected_hash: Option<Vec<u8>>,
    pub max_retry: i64,
    pub packet_payload_size: i64,
    pub packets_per_fec: i64,
    pub fec_slice_stride: i64,
}

impl Default for AsrServerConfig {
    fn default() -> Self {
        Self {
            payload_size: None,
            stream_id: 1,
            image_name: None,
            uuid: None,
            checksum_chunk_size: super::payload::DEFAULT_BLOCK_LEN as u64,
            checksum_type: ChecksumType::Sha256,
            metadata: None,
            expected_hash: None,
            max_retry: super::message::DEFAULT_MAX_RETRY,
            packet_payload_size: super::message::DEFAULT_PACKET_PAYLOAD_SIZE,
            packets_per_fec: super::message::DEFAULT_PACKETS_PER_FEC,
            fec_slice_stride: super::message::DEFAULT_FEC_SLICE_STRIDE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Negotiation {
    plan: PayloadPlan,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct SessionSummary {
    pub initiates: u32,
    pub metadata_requests: u32,
    pub oob_single_requests: u32,
    pub oob_ranges_requests: u32,
    pub oob_bytes: u64,
    pub payload: Option<PayloadSummary>,
}

pub struct AsrSession<S> {
    source: S,
    config: AsrServerConfig,
    payload_size: u64,
    negotiation: Option<Negotiation>,
    summary: SessionSummary,
}

impl<S: ImageSource> AsrSession<S> {
    pub fn new(source: S, config: AsrServerConfig) -> Result<Self, AsrError> {
        let payload_size = config.payload_size.unwrap_or_else(|| source.len());
        if payload_size > source.len() {
            return Err(AsrError::PayloadExceedsSource {
                requested: payload_size,
                available: source.len(),
            });
        }
        Ok(Self {
            source,
            config,
            payload_size,
            negotiation: None,
            summary: SessionSummary::default(),
        })
    }

    pub fn payload_size(&self) -> u64 {
        self.payload_size
    }

    pub fn summary(&self) -> &SessionSummary {
        &self.summary
    }

    pub fn stream_digest_kind(&self) -> StreamDigestKind {
        StreamDigestKind::for_expected_hash_len(
            self.config
                .expected_hash
                .as_ref()
                .map_or(0, |hash| hash.len()),
        )
    }

    // `restored` and then asr each send their own `Initiate` on this one connection, so it arrives
    // more than once and each renegotiates; only `Payload` ends the conversation.
    pub fn serve<T, O>(
        &mut self,
        transport: &mut T,
        observer: &mut O,
    ) -> Result<SessionSummary, AsrError>
    where
        T: Read + Write + ?Sized,
        O: PayloadObserver + ?Sized,
    {
        let mut reader = PlistReader::new(transport);
        loop {
            observer.entered_phase(AsrPhase::AwaitingRequest, 0);
            let request = match reader.read_request()? {
                Some(request) => request,
                None => break,
            };
            match request.command {
                Command::Initiate => {
                    observer.entered_phase(AsrPhase::AnsweringInitiate, 0);
                    let response = self.answer_initiate(&request);
                    codec::write_plist(reader.get_mut(), &response.to_value())?;
                    self.summary.initiates += 1;
                }
                Command::Metadata => {
                    observer.entered_phase(AsrPhase::ServingMetadata, 0);
                    let blob = self
                        .config
                        .metadata
                        .as_ref()
                        .ok_or(AsrError::MetadataNotOffered)?;
                    let bytes = blob.bytes.clone();
                    reader.get_mut().write_all(&bytes)?;
                    reader.get_mut().flush()?;
                    self.summary.metadata_requests += 1;
                }
                Command::OobData => {
                    observer.entered_phase(AsrPhase::ServingOob, 0);
                    if request.body.contains_key(KEY_OOB_RANGES) {
                        let response = self.answer_oob_ranges(&request)?;
                        reader.get_mut().write_all(&response)?;
                        reader.get_mut().flush()?;
                        self.summary.oob_ranges_requests += 1;
                        // The end of file that delimits this answer belongs to the socket asr opened
                        // for the request, not to this transport: do not close here.
                    } else {
                        let served = self.answer_oob_single(&request, reader.get_mut())?;
                        self.summary.oob_single_requests += 1;
                        self.summary.oob_bytes += served;
                    }
                }
                Command::Payload => {
                    let plan = self
                        .negotiation
                        .ok_or(AsrError::PayloadBeforeInitiate)?
                        .plan;
                    let summary =
                        stream_payload(&mut self.source, reader.get_mut(), &plan, observer)?;
                    if let Some(expected) = &self.config.expected_hash
                        && !summary.stopped_early
                        && summary.stream_digest != *expected
                    {
                        return Err(AsrError::StreamDigestMismatch {
                            expected: expected.clone(),
                            actual: summary.stream_digest,
                        });
                    }
                    self.summary.payload = Some(summary);
                    break;
                }
            }
        }
        Ok(self.summary.clone())
    }

    fn answer_initiate(&mut self, request: &Request) -> InitiateResponse {
        let asked = InitiateRequest::from_request(request);

        let mut response = InitiateResponse::new(
            StreamDescriptor::on_control_connection(self.payload_size as i64),
            self.config.stream_id,
        );
        response.packet_payload_size = self.config.packet_payload_size;
        response.packets_per_fec = self.config.packets_per_fec;
        response.fec_slice_stride = self.config.fec_slice_stride;
        response.max_retry = self.config.max_retry;
        response.uuid = self.config.uuid.clone();
        response.image_name = self.config.image_name.clone().or(asked.image_name);
        response.metadata = self.config.metadata.as_ref().map(MetadataBlob::descriptor);

        if asked.wants_checksum_chunks && self.config.checksum_chunk_size > 0 {
            response.checksum_chunk_size = Some(self.config.checksum_chunk_size as i64);
            response.checksum_type = Some(
                asked
                    .preferred_checksum_type
                    .unwrap_or(self.config.checksum_type),
            );
        }

        self.negotiation = Some(Negotiation {
            plan: PayloadPlan {
                size: self.payload_size,
                checksum_chunk_size: response.effective_chunk_size(),
                checksum_type: response.effective_checksum_type(),
                stream_digest: self.stream_digest_kind(),
            },
        });
        response
    }

    fn answer_oob_single<W: Write + ?Sized>(
        &mut self,
        request: &Request,
        out: &mut W,
    ) -> Result<u64, AsrError> {
        let (offset, length) = oob_range(&request.body)?;
        let mut buffer = vec![0u8; length];
        self.read_oob(offset, &mut buffer)?;
        out.write_all(&buffer)?;
        out.flush()?;
        Ok(length as u64)
    }

    fn answer_oob_ranges(&mut self, request: &Request) -> Result<Vec<u8>, AsrError> {
        let ranges = request
            .body
            .get(KEY_OOB_RANGES)
            .and_then(Value::as_array)
            .ok_or(AsrError::MalformedOob("OOB Ranges is not an array"))?
            .clone();

        let mut answers = Vec::with_capacity(ranges.len());
        for entry in &ranges {
            let dict = entry.as_dictionary().ok_or(AsrError::MalformedOob(
                "an OOB Ranges element is not a dictionary",
            ))?;
            let (offset, length) = oob_range(dict)?;
            let mut answer = Dictionary::new();
            answer.insert(
                KEY_OOB_OFFSET.to_string(),
                Value::Integer(Integer::from(offset as i64)),
            );
            let mut buffer = vec![0u8; length];
            match self.read_oob(offset, &mut buffer) {
                Ok(()) => {
                    self.summary.oob_bytes += length as u64;
                    answer.insert(KEY_OOB_CHUNK.to_string(), Value::Data(buffer));
                }
                Err(_) => {
                    answer.insert(
                        KEY_OOB_ERROR.to_string(),
                        Value::Integer(Integer::from(OOB_READ_ERROR)),
                    );
                }
            }
            answers.push(Value::Dictionary(answer));
        }

        let mut response = Dictionary::new();
        response.insert(KEY_OOB_RANGES.to_string(), Value::Array(answers));
        let xml = codec::encode_plist(&Value::Dictionary(response))?;
        Ok(deflate::gzip_compress(&xml))
    }

    fn read_oob(&mut self, offset: u64, buffer: &mut [u8]) -> Result<(), AsrError> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .ok_or(AsrError::OobOutOfRange {
                offset,
                length: buffer.len() as u64,
                size: self.payload_size,
            })?;
        if end > self.payload_size {
            return Err(AsrError::OobOutOfRange {
                offset,
                length: buffer.len() as u64,
                size: self.payload_size,
            });
        }
        self.source.read_exact_at(offset, buffer)?;
        Ok(())
    }
}

fn oob_range(dict: &Dictionary) -> Result<(u64, usize), AsrError> {
    let offset =
        codec::dict_integer(dict, KEY_OOB_OFFSET).ok_or(AsrError::MalformedOob("no OOB Offset"))?;
    let length =
        codec::dict_integer(dict, KEY_OOB_LENGTH).ok_or(AsrError::MalformedOob("no OOB Length"))?;
    if offset < 0 || length < 0 {
        return Err(AsrError::MalformedOob("negative OOB Offset or OOB Length"));
    }
    let length =
        usize::try_from(length).map_err(|_| AsrError::MalformedOob("OOB Length too large"))?;
    Ok((offset as u64, length))
}

pub fn connect_and_serve<A, S, O>(
    address: A,
    session: &mut AsrSession<S>,
    observer: &mut O,
) -> Result<SessionSummary, AsrError>
where
    A: ToSocketAddrs,
    S: ImageSource,
    O: PayloadObserver + ?Sized,
{
    let mut stream = TcpStream::connect(address)?;
    stream.set_nodelay(true)?;
    session.serve(&mut stream, observer)
}

#[derive(Debug)]
pub enum AsrError {
    Io(io::Error),
    Codec(codec::CodecError),
    Metadata(MetadataError),
    PayloadExceedsSource { requested: u64, available: u64 },
    PayloadBeforeInitiate,
    MetadataNotOffered,
    MalformedOob(&'static str),
    OobOutOfRange { offset: u64, length: u64, size: u64 },
    StreamDigestMismatch { expected: Vec<u8>, actual: Vec<u8> },
}

impl std::fmt::Display for AsrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Codec(err) => write!(f, "{err}"),
            Self::Metadata(err) => write!(f, "{err}"),
            Self::PayloadExceedsSource {
                requested,
                available,
            } => write!(
                f,
                "payload of {requested} bytes exceeds the {available} byte source"
            ),
            Self::PayloadBeforeInitiate => {
                f.write_str("Payload requested before any Initiate negotiated a stream")
            }
            Self::MetadataNotOffered => {
                f.write_str("Metadata requested but no metadata blob was offered")
            }
            Self::MalformedOob(reason) => write!(f, "malformed OOBData request: {reason}"),
            Self::OobOutOfRange {
                offset,
                length,
                size,
            } => write!(
                f,
                "out of band range [{offset}, {length}] falls outside the {size} byte payload"
            ),
            Self::StreamDigestMismatch { expected, actual } => write!(
                f,
                "stream digest {} does not match the expected {}",
                hex(actual),
                hex(expected)
            ),
        }
    }
}

impl std::error::Error for AsrError {}

impl From<io::Error> for AsrError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<codec::CodecError> for AsrError {
    fn from(err: codec::CodecError) -> Self {
        Self::Codec(err)
    }
}

impl From<MetadataError> for AsrError {
    fn from(err: MetadataError) -> Self {
        Self::Metadata(err)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::codec::encode_plist;
    use super::super::message::{
        KEY_CHECKSUM_CHUNK_SIZE, KEY_CHECKSUM_CHUNKS, KEY_CHECKSUM_TYPE, KEY_METADATA, KEY_PAYLOAD,
        KEY_SIZE,
    };
    use super::super::metadata::ImageChunk;
    use super::super::source::MemoryImageSource;
    use super::*;

    struct ScriptedTransport {
        inbound: Vec<u8>,
        read_cursor: usize,
        outbound: Vec<u8>,
        write_shutdown: bool,
    }

    impl ScriptedTransport {
        fn new(requests: &[Value]) -> Self {
            let mut inbound = Vec::new();
            for request in requests {
                inbound.extend_from_slice(&encode_plist(request).unwrap());
            }
            Self {
                inbound,
                read_cursor: 0,
                outbound: Vec::new(),
                write_shutdown: false,
            }
        }
    }

    impl Read for ScriptedTransport {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.inbound[self.read_cursor..];
            let count = remaining.len().min(buf.len());
            buf[..count].copy_from_slice(&remaining[..count]);
            self.read_cursor += count;
            Ok(count)
        }
    }

    impl Write for ScriptedTransport {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            assert!(!self.write_shutdown, "wrote after the write side was shut");
            self.outbound.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl AsrTransport for ScriptedTransport {
        fn shutdown_write(&mut self) -> io::Result<()> {
            self.write_shutdown = true;
            Ok(())
        }
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn initiate(with_checksums: bool) -> Value {
        let mut request = Request::new(Command::Initiate);
        if with_checksums {
            request
                .body
                .insert(KEY_CHECKSUM_CHUNKS.to_string(), Value::Boolean(true));
            request.body.insert(
                KEY_CHECKSUM_TYPE.to_string(),
                Value::Integer(Integer::from(1)),
            );
        }
        request.to_value()
    }

    fn oob(offset: i64, length: i64) -> Value {
        Request::new(Command::OobData)
            .with_integer(KEY_OOB_OFFSET, offset)
            .with_integer(KEY_OOB_LENGTH, length)
            .to_value()
    }

    fn split_first_plist(out: &[u8]) -> (Value, &[u8]) {
        let tag = b"</plist>";
        let end = out
            .windows(tag.len())
            .position(|window| window == tag)
            .expect("a plist response")
            + tag.len();
        let value = Value::from_reader_xml(io::Cursor::new(&out[..end])).unwrap();
        (value, &out[end..])
    }

    #[test]
    fn a_bare_initiate_is_answered_with_the_mandatory_key_set_and_no_checksum_keys() {
        let image = body(4096);
        let mut session =
            AsrSession::new(MemoryImageSource::new(image), AsrServerConfig::default()).unwrap();
        let mut transport = ScriptedTransport::new(&[initiate(false)]);
        let summary = session.serve(&mut transport, &mut ()).unwrap();

        assert_eq!(summary.initiates, 1);
        let (value, rest) = split_first_plist(&transport.outbound);
        assert!(rest.is_empty(), "nothing may follow the response plist");
        let dict = value.as_dictionary().unwrap();
        assert_eq!(dict.get("Version").unwrap().as_signed_integer(), Some(1));
        assert!(dict.contains_key("Stream ID"));
        assert!(!dict.contains_key(KEY_CHECKSUM_CHUNK_SIZE));
        let payload = dict.get(KEY_PAYLOAD).unwrap().as_dictionary().unwrap();
        assert_eq!(
            payload.get(KEY_SIZE).unwrap().as_signed_integer(),
            Some(4096)
        );
        assert!(!payload.contains_key("Family"));
        assert!(!payload.contains_key("Address"));
    }

    #[test]
    fn asking_for_checksum_chunks_is_what_turns_the_two_checksum_keys_on() {
        let mut session = AsrSession::new(
            MemoryImageSource::new(body(4096)),
            AsrServerConfig {
                checksum_chunk_size: 1024,
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        let mut transport = ScriptedTransport::new(&[initiate(true)]);
        session.serve(&mut transport, &mut ()).unwrap();

        let (value, _) = split_first_plist(&transport.outbound);
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict.get(KEY_CHECKSUM_CHUNK_SIZE)
                .unwrap()
                .as_signed_integer(),
            Some(1024)
        );
        assert_eq!(
            dict.get(KEY_CHECKSUM_TYPE).unwrap().as_signed_integer(),
            Some(1)
        );
    }

    #[test]
    fn a_single_range_oob_request_is_answered_with_raw_bytes_and_no_plist() {
        let image = body(4096);
        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig::default(),
        )
        .unwrap();
        let mut transport = ScriptedTransport::new(&[oob(0, 64)]);
        let summary = session.serve(&mut transport, &mut ()).unwrap();

        assert_eq!(summary.oob_single_requests, 1);
        assert_eq!(summary.oob_bytes, 64);
        assert_eq!(transport.outbound, image[..64]);
    }

    #[test]
    fn an_interior_oob_range_reads_from_the_right_offset() {
        let image = body(8192);
        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig::default(),
        )
        .unwrap();
        let mut transport = ScriptedTransport::new(&[oob(4000, 300)]);
        session.serve(&mut transport, &mut ()).unwrap();
        assert_eq!(transport.outbound, image[4000..4300]);
    }

    #[test]
    fn an_oob_range_past_the_payload_is_refused() {
        let mut session = AsrSession::new(
            MemoryImageSource::new(body(1024)),
            AsrServerConfig::default(),
        )
        .unwrap();
        let mut transport = ScriptedTransport::new(&[oob(1000, 64)]);
        match session.serve(&mut transport, &mut ()) {
            Err(AsrError::OobOutOfRange {
                offset,
                length,
                size,
            }) => {
                assert_eq!((offset, length, size), (1000, 64, 1024));
            }
            other => panic!("expected OobOutOfRange, got {other:?}"),
        }
        assert!(transport.outbound.is_empty());
    }

    #[test]
    fn the_restored_then_asr_sequence_runs_on_one_connection() {
        let image = body(4096);
        let metadata = ImageMetadata {
            image_size: 4096,
            chunks: vec![ImageChunk::new(0x20, b"NXSB".to_vec())],
            partitions: None,
            filesystems: None,
        };
        let blob = MetadataBlob::gzip(&metadata).unwrap().with_checksum();
        let blob_bytes = blob.bytes().to_vec();

        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig {
                checksum_chunk_size: 1024,
                metadata: Some(blob),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();

        let mut transport = ScriptedTransport::new(&[
            initiate(false),
            oob(0, 64),
            initiate(true),
            Request::new(Command::Metadata).to_value(),
            Request::new(Command::Payload).to_value(),
        ]);
        let summary = session.serve(&mut transport, &mut ()).unwrap();

        assert_eq!(summary.initiates, 2);
        assert_eq!(summary.oob_single_requests, 1);
        assert_eq!(summary.metadata_requests, 1);
        let payload = summary.payload.as_ref().unwrap();
        assert_eq!(payload.data_bytes, 4096);
        assert_eq!(payload.blocks, 4);

        let out = &transport.outbound[..];
        let (first, rest) = split_first_plist(out);
        assert!(
            !first
                .as_dictionary()
                .unwrap()
                .contains_key(KEY_CHECKSUM_CHUNK_SIZE)
        );
        assert!(first.as_dictionary().unwrap().contains_key(KEY_METADATA));

        assert_eq!(&rest[..64], &image[..64]);
        let rest = &rest[64..];

        let (second, rest) = split_first_plist(rest);
        assert!(
            second
                .as_dictionary()
                .unwrap()
                .contains_key(KEY_CHECKSUM_CHUNK_SIZE)
        );

        assert_eq!(&rest[..blob_bytes.len()], &blob_bytes[..]);
        let rest = &rest[blob_bytes.len()..];

        assert_eq!(rest.len(), 4096 + 4 * 32);
        let mut cursor = 0usize;
        for index in 0..4usize {
            let data = &rest[cursor..cursor + 1024];
            cursor += 1024;
            let digest = &rest[cursor..cursor + 32];
            cursor += 32;
            assert_eq!(data, &image[index * 1024..(index + 1) * 1024]);
            assert_eq!(digest, &ChecksumType::Sha256.digest(data)[..]);
        }
    }

    #[test]
    fn a_metadata_descriptor_announces_the_blob_length_and_its_sha1() {
        let metadata = ImageMetadata::for_image_size(4096);
        let blob = MetadataBlob::plain(&metadata).unwrap().with_checksum();
        let expected_len = blob.bytes().len() as i64;
        let expected_sha1 = ChecksumType::Sha1.digest(blob.bytes());

        let mut session = AsrSession::new(
            MemoryImageSource::new(body(4096)),
            AsrServerConfig {
                metadata: Some(blob),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        let mut transport = ScriptedTransport::new(&[initiate(false)]);
        session.serve(&mut transport, &mut ()).unwrap();

        let (value, _) = split_first_plist(&transport.outbound);
        let descriptor = value
            .as_dictionary()
            .unwrap()
            .get(KEY_METADATA)
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert_eq!(
            descriptor.get(KEY_SIZE).unwrap().as_signed_integer(),
            Some(expected_len)
        );
        assert_eq!(
            descriptor.get("Checksum").unwrap().as_data(),
            Some(&expected_sha1[..])
        );
        assert!(!descriptor.contains_key("Address"));
    }

    #[test]
    fn a_metadata_request_without_an_offered_blob_is_refused() {
        let mut session =
            AsrSession::new(MemoryImageSource::new(body(64)), AsrServerConfig::default()).unwrap();
        let mut transport = ScriptedTransport::new(&[Request::new(Command::Metadata).to_value()]);
        assert!(matches!(
            session.serve(&mut transport, &mut ()),
            Err(AsrError::MetadataNotOffered)
        ));
    }

    #[test]
    fn a_payload_request_before_any_initiate_is_refused() {
        let mut session =
            AsrSession::new(MemoryImageSource::new(body(64)), AsrServerConfig::default()).unwrap();
        let mut transport = ScriptedTransport::new(&[Request::new(Command::Payload).to_value()]);
        assert!(matches!(
            session.serve(&mut transport, &mut ()),
            Err(AsrError::PayloadBeforeInitiate)
        ));
    }

    #[test]
    fn a_client_that_never_asked_for_checksums_gets_plain_payload_bytes() {
        let image = body(3000);
        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig::default(),
        )
        .unwrap();
        let mut transport =
            ScriptedTransport::new(&[initiate(false), Request::new(Command::Payload).to_value()]);
        session.serve(&mut transport, &mut ()).unwrap();

        let (_, rest) = split_first_plist(&transport.outbound);
        assert_eq!(rest, &image[..]);
    }

    #[test]
    fn the_expected_hash_is_checked_against_the_bytes_actually_served() {
        let image = body(2048);
        let good = StreamDigestKind::Sha384.digest(&image);

        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig {
                expected_hash: Some(good.clone()),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        assert_eq!(session.stream_digest_kind(), StreamDigestKind::Sha384);
        let mut transport =
            ScriptedTransport::new(&[initiate(false), Request::new(Command::Payload).to_value()]);
        session.serve(&mut transport, &mut ()).unwrap();

        let mut session = AsrSession::new(
            MemoryImageSource::new(image),
            AsrServerConfig {
                expected_hash: Some(vec![0u8; 48]),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        let mut transport =
            ScriptedTransport::new(&[initiate(false), Request::new(Command::Payload).to_value()]);
        match session.serve(&mut transport, &mut ()) {
            Err(AsrError::StreamDigestMismatch { actual, .. }) => assert_eq!(actual, good),
            other => panic!("expected StreamDigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_twenty_byte_expected_hash_selects_sha1_for_the_whole_stream() {
        let session = AsrSession::new(
            MemoryImageSource::new(body(16)),
            AsrServerConfig {
                expected_hash: Some(vec![0u8; 20]),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        assert_eq!(session.stream_digest_kind(), StreamDigestKind::Sha1);
    }

    fn oob_ranges(ranges: &[(i64, i64)]) -> Value {
        let mut entries = Vec::new();
        for (offset, length) in ranges {
            let mut entry = Dictionary::new();
            entry.insert(
                KEY_OOB_OFFSET.to_string(),
                Value::Integer(Integer::from(*offset)),
            );
            entry.insert(
                KEY_OOB_LENGTH.to_string(),
                Value::Integer(Integer::from(*length)),
            );
            entries.push(Value::Dictionary(entry));
        }
        let mut request = Request::new(Command::OobData);
        request
            .body
            .insert(KEY_OOB_RANGES.to_string(), Value::Array(entries));
        request.to_value()
    }

    #[test]
    fn a_vectored_oob_answer_leaves_the_transport_open_for_the_rest_of_the_conversation() {
        let image = body(4096);
        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig {
                checksum_chunk_size: 0,
                ..AsrServerConfig::default()
            },
        )
        .unwrap();

        let mut transport = ScriptedTransport::new(&[
            oob_ranges(&[(0, 32)]),
            initiate(false),
            Request::new(Command::Payload).to_value(),
        ]);
        let summary = session.serve(&mut transport, &mut ()).unwrap();

        assert_eq!(summary.oob_ranges_requests, 1);
        assert!(
            !transport.write_shutdown,
            "the control transport must survive a vectored answer"
        );
        assert_eq!(summary.initiates, 1, "the Initiate after it must be served");
        let payload = summary
            .payload
            .expect("the Payload after a vectored answer must still be streamed");
        assert_eq!(payload.data_bytes, 4096);
        assert!(!payload.stopped_early);

        assert!(transport.outbound.ends_with(&image));
    }

    #[test]
    fn the_vectored_oob_form_is_answered_inline_with_a_deflated_plist() {
        let image = body(4096);
        let mut session = AsrSession::new(
            MemoryImageSource::new(image.clone()),
            AsrServerConfig::default(),
        )
        .unwrap();

        let mut ranges = Vec::new();
        for (offset, length) in [(0i64, 32i64), (1024, 16)] {
            let mut entry = Dictionary::new();
            entry.insert(
                KEY_OOB_OFFSET.to_string(),
                Value::Integer(Integer::from(offset)),
            );
            entry.insert(
                KEY_OOB_LENGTH.to_string(),
                Value::Integer(Integer::from(length)),
            );
            ranges.push(Value::Dictionary(entry));
        }
        let mut request = Request::new(Command::OobData);
        request
            .body
            .insert(KEY_OOB_RANGES.to_string(), Value::Array(ranges));

        let mut transport = ScriptedTransport::new(&[request.to_value()]);
        let summary = session.serve(&mut transport, &mut ()).unwrap();

        assert_eq!(summary.oob_ranges_requests, 1);
        assert!(!transport.write_shutdown);

        let xml = deflate::gzip_decompress(&transport.outbound).unwrap();
        let value = Value::from_reader_xml(io::Cursor::new(xml)).unwrap();
        let answers = value
            .as_dictionary()
            .unwrap()
            .get(KEY_OOB_RANGES)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(answers.len(), 2);
        let first = answers[0].as_dictionary().unwrap();
        assert_eq!(
            first.get(KEY_OOB_OFFSET).unwrap().as_signed_integer(),
            Some(0)
        );
        assert_eq!(
            first.get(KEY_OOB_CHUNK).unwrap().as_data(),
            Some(&image[..32])
        );
        let second = answers[1].as_dictionary().unwrap();
        assert_eq!(
            second.get(KEY_OOB_CHUNK).unwrap().as_data(),
            Some(&image[1024..1040])
        );
    }

    #[test]
    fn a_vectored_range_that_cannot_be_read_reports_oob_error_in_place() {
        let mut session = AsrSession::new(
            MemoryImageSource::new(body(1024)),
            AsrServerConfig::default(),
        )
        .unwrap();

        let mut entry = Dictionary::new();
        entry.insert(
            KEY_OOB_OFFSET.to_string(),
            Value::Integer(Integer::from(1000)),
        );
        entry.insert(
            KEY_OOB_LENGTH.to_string(),
            Value::Integer(Integer::from(64)),
        );
        let mut request = Request::new(Command::OobData);
        request.body.insert(
            KEY_OOB_RANGES.to_string(),
            Value::Array(vec![Value::Dictionary(entry)]),
        );

        let mut transport = ScriptedTransport::new(&[request.to_value()]);
        session.serve(&mut transport, &mut ()).unwrap();

        let xml = deflate::gzip_decompress(&transport.outbound).unwrap();
        let value = Value::from_reader_xml(io::Cursor::new(xml)).unwrap();
        let answers = value
            .as_dictionary()
            .unwrap()
            .get(KEY_OOB_RANGES)
            .unwrap()
            .as_array()
            .unwrap();
        let first = answers[0].as_dictionary().unwrap();
        assert!(first.contains_key(KEY_OOB_ERROR));
        assert!(!first.contains_key(KEY_OOB_CHUNK));
    }

    #[test]
    fn a_payload_shorter_than_the_source_is_what_the_descriptor_advertises() {
        let mut session = AsrSession::new(
            MemoryImageSource::new(body(8192)),
            AsrServerConfig {
                payload_size: Some(4096),
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        assert_eq!(session.payload_size(), 4096);
        let mut transport = ScriptedTransport::new(&[initiate(false)]);
        session.serve(&mut transport, &mut ()).unwrap();
        let (value, _) = split_first_plist(&transport.outbound);
        let payload = value
            .as_dictionary()
            .unwrap()
            .get(KEY_PAYLOAD)
            .unwrap()
            .as_dictionary()
            .unwrap();
        assert_eq!(
            payload.get(KEY_SIZE).unwrap().as_signed_integer(),
            Some(4096)
        );
    }

    #[test]
    fn a_payload_longer_than_the_source_is_refused_at_construction() {
        assert!(matches!(
            AsrSession::new(
                MemoryImageSource::new(body(16)),
                AsrServerConfig {
                    payload_size: Some(64),
                    ..AsrServerConfig::default()
                },
            ),
            Err(AsrError::PayloadExceedsSource {
                requested: 64,
                available: 16
            })
        ));
    }

    #[test]
    fn a_real_socket_runs_the_conversation_in_the_direction_the_protocol_uses() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let image = body(9000);
        let expected = image.clone();

        let client = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = PlistReader::new(stream);

            let mut request = Request::new(Command::Initiate);
            request
                .body
                .insert(KEY_CHECKSUM_CHUNKS.to_string(), Value::Boolean(true));
            request.body.insert(
                KEY_CHECKSUM_TYPE.to_string(),
                Value::Integer(Integer::from(1)),
            );
            codec::write_plist(reader.get_mut(), &request.to_value()).unwrap();

            let response = reader.read_value().unwrap().unwrap();
            let dict = response.as_dictionary().unwrap().clone();
            let size = dict
                .get(KEY_PAYLOAD)
                .unwrap()
                .as_dictionary()
                .unwrap()
                .get(KEY_SIZE)
                .unwrap()
                .as_signed_integer()
                .unwrap() as usize;
            let block_len = dict
                .get(KEY_CHECKSUM_CHUNK_SIZE)
                .unwrap()
                .as_signed_integer()
                .unwrap() as usize;
            let checksum_type = ChecksumType::from_wire(
                dict.get(KEY_CHECKSUM_TYPE)
                    .unwrap()
                    .as_signed_integer()
                    .unwrap(),
            )
            .unwrap();
            let digest_len = checksum_type.digest_len();

            codec::write_plist(reader.get_mut(), &Request::new(Command::Payload).to_value())
                .unwrap();

            let mut data = Vec::with_capacity(size);
            let mut done = 0usize;
            while done < size {
                let data_len = block_len.min(size - done);
                let mut block = vec![0u8; data_len + digest_len];
                reader.get_mut().read_exact(&mut block).unwrap();
                let (payload, digest) = block.split_at(data_len);
                assert_eq!(digest, &checksum_type.digest(payload)[..]);
                data.extend_from_slice(payload);
                done += data_len;
            }
            let mut trailing = Vec::new();
            reader.get_mut().read_to_end(&mut trailing).unwrap();
            assert!(trailing.is_empty());
            data
        });

        let mut session = AsrSession::new(
            MemoryImageSource::new(image),
            AsrServerConfig {
                checksum_chunk_size: 4096,
                ..AsrServerConfig::default()
            },
        )
        .unwrap();
        let summary = connect_and_serve(address, &mut session, &mut ()).unwrap();

        assert_eq!(summary.initiates, 1);
        assert_eq!(summary.payload.as_ref().unwrap().data_bytes, 9000);
        assert_eq!(summary.payload.as_ref().unwrap().blocks, 3);
        assert_eq!(client.join().unwrap(), expected);
    }
}
