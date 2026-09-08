use std::fmt;
use std::io::{self, Read, Write};

use plist::Value;

pub const LENGTH_PREFIX_LEN: usize = 4;

pub const MAX_MESSAGE_LEN: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum PlistFormat {
    #[default]
    Binary,
    Xml,
}

pub fn encode_message(value: &Value, format: PlistFormat) -> Result<Vec<u8>, CodecError> {
    let mut body = Vec::new();
    match format {
        PlistFormat::Binary => value.to_writer_binary(&mut body)?,
        PlistFormat::Xml => value.to_writer_xml(&mut body)?,
    }
    if body.len() > MAX_MESSAGE_LEN {
        return Err(CodecError::MessageTooLarge {
            announced: body.len() as u64,
        });
    }
    let prefix = (body.len() as u32).to_be_bytes();
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_LEN + body.len());
    framed.extend_from_slice(&prefix);
    framed.append(&mut body);
    Ok(framed)
}

pub fn write_message<W: Write>(
    writer: &mut W,
    value: &Value,
    format: PlistFormat,
) -> Result<usize, CodecError> {
    let framed = encode_message(value, format)?;
    let write_err = |error: io::Error| {
        CodecError::Io(io::Error::new(
            error.kind(),
            format!("{error} while writing {} framed bytes", framed.len()),
        ))
    };
    writer.write_all(&framed).map_err(write_err)?;
    writer.flush().map_err(write_err)?;
    Ok(framed.len())
}

pub fn read_message<R: Read>(reader: &mut R) -> Result<Option<Value>, CodecError> {
    let mut prefix = [0u8; LENGTH_PREFIX_LEN];
    match read_fully(reader, &mut prefix)? {
        Filled::Empty => return Ok(None),
        Filled::Partial(read) => {
            return Err(CodecError::Truncated {
                expected: LENGTH_PREFIX_LEN as u64,
                received: read as u64,
                part: "length prefix",
            });
        }
        Filled::Complete => {}
    }

    let announced = u32::from_be_bytes(prefix) as u64;
    if announced == 0 {
        return Err(CodecError::EmptyMessage);
    }
    if announced > MAX_MESSAGE_LEN as u64 {
        return Err(CodecError::MessageTooLarge { announced });
    }
    let mut body = vec![0u8; announced as usize];
    match read_fully(reader, &mut body)? {
        Filled::Complete => {}
        Filled::Empty => {
            return Err(CodecError::Truncated {
                expected: announced,
                received: 0,
                part: "body",
            });
        }
        Filled::Partial(read) => {
            return Err(CodecError::Truncated {
                expected: announced,
                received: read as u64,
                part: "body",
            });
        }
    }

    let value = Value::from_reader(io::Cursor::new(body))?;
    Ok(Some(value))
}

enum Filled {
    Complete,
    Empty,
    Partial(usize),
}

fn read_fully<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<Filled, CodecError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    Filled::Empty
                } else {
                    Filled::Partial(filled)
                });
            }
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(CodecError::Io(error)),
        }
    }
    Ok(Filled::Complete)
}

#[derive(Debug)]
pub enum CodecError {
    Io(io::Error),
    Plist(plist::Error),
    MessageTooLarge {
        announced: u64,
    },
    EmptyMessage,
    Truncated {
        expected: u64,
        received: u64,
        part: &'static str,
    },
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "{error}"),
            Self::Plist(error) => write!(f, "{error}"),
            Self::MessageTooLarge { announced } => write!(
                f,
                "message of {announced} bytes exceeds the {MAX_MESSAGE_LEN} byte limit"
            ),
            Self::EmptyMessage => f.write_str("length prefix announced a zero-byte message body"),
            Self::Truncated {
                expected,
                received,
                part,
            } => write!(
                f,
                "connection closed after {received} of {expected} bytes of message {part}"
            ),
        }
    }
}

impl std::error::Error for CodecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Plist(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CodecError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<plist::Error> for CodecError {
    fn from(error: plist::Error) -> Self {
        Self::Plist(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plist::{Dictionary, Integer};

    fn dict(pairs: &[(&str, &str)]) -> Value {
        let mut body = Dictionary::new();
        for (key, value) in pairs {
            body.insert((*key).to_string(), Value::String((*value).to_string()));
        }
        Value::Dictionary(body)
    }

    struct DribbleReader {
        bytes: Vec<u8>,
        cursor: usize,
        chunk: usize,
    }

    impl Read for DribbleReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let remaining = &self.bytes[self.cursor..];
            let count = remaining.len().min(buf.len()).min(self.chunk);
            buf[..count].copy_from_slice(&remaining[..count]);
            self.cursor += count;
            Ok(count)
        }
    }

    struct OneByteWriter {
        written: Vec<u8>,
    }

    impl Write for OneByteWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.written.push(buf[0]);
            Ok(1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_prefix_is_four_bytes_big_endian_and_counts_only_the_body() {
        let framed = encode_message(&dict(&[("Request", "QueryType")]), PlistFormat::Binary)
            .expect("encodes");
        let announced = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(
            announced,
            framed.len() - LENGTH_PREFIX_LEN,
            "the prefix counts the body and excludes itself"
        );
        assert_eq!(framed[0], 0);
        assert_ne!(framed[3], 0);
    }

    #[test]
    fn the_default_serialisation_is_bplist00_which_is_what_the_guest_emits() {
        let framed =
            encode_message(&dict(&[("Request", "QueryType")]), PlistFormat::default()).unwrap();
        assert_eq!(
            &framed[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + 8],
            b"bplist00"
        );
    }

    #[test]
    fn xml_framing_announces_the_xml_body_length() {
        let value = dict(&[("Request", "QueryType")]);
        let framed = encode_message(&value, PlistFormat::Xml).unwrap();
        let announced = u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize;
        assert_eq!(announced, framed.len() - LENGTH_PREFIX_LEN);
        let body = &framed[LENGTH_PREFIX_LEN..];
        assert!(body.starts_with(b"<?xml"), "an XML document was requested");
        assert_eq!(read_message(&mut &framed[..]).unwrap().unwrap(), value);
    }

    #[test]
    fn a_binary_round_trip_preserves_the_document() {
        let value = dict(&[("Request", "StartRestore"), ("Variant", "Customer")]);
        let framed = encode_message(&value, PlistFormat::Binary).unwrap();
        let decoded = read_message(&mut &framed[..]).unwrap().unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn both_serialisations_decode_through_one_reader() {
        let value = dict(&[("MsgType", "ProgressMsg")]);
        for format in [PlistFormat::Binary, PlistFormat::Xml] {
            let framed = encode_message(&value, format).unwrap();
            let decoded = read_message(&mut &framed[..]).unwrap().unwrap();
            assert_eq!(decoded, value, "{format:?} did not round-trip");
        }
    }

    #[test]
    fn a_frame_split_one_byte_at_a_time_still_reads() {
        let value = dict(&[("Request", "QueryValue"), ("QueryKey", "SerialNumber")]);
        let framed = encode_message(&value, PlistFormat::Binary).unwrap();
        let mut reader = DribbleReader {
            bytes: framed,
            cursor: 0,
            chunk: 1,
        };
        assert_eq!(read_message(&mut reader).unwrap().unwrap(), value);
    }

    #[test]
    fn two_frames_coalesced_into_one_buffer_read_back_in_order() {
        let first = dict(&[("Request", "QueryType")]);
        let second = dict(&[("Request", "Goodbye")]);
        let mut stream = encode_message(&first, PlistFormat::Binary).unwrap();
        stream.extend_from_slice(&encode_message(&second, PlistFormat::Binary).unwrap());
        let mut cursor = &stream[..];
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), first);
        assert_eq!(read_message(&mut cursor).unwrap().unwrap(), second);
        assert!(
            read_message(&mut cursor).unwrap().is_none(),
            "the stream ended at a frame boundary"
        );
    }

    #[test]
    fn a_clean_close_at_a_frame_boundary_is_not_an_error() {
        let mut empty: &[u8] = &[];
        assert!(read_message(&mut empty).unwrap().is_none());
    }

    #[test]
    fn a_close_inside_the_prefix_is_truncation_not_a_clean_end() {
        let mut partial: &[u8] = &[0x00, 0x00];
        match read_message(&mut partial) {
            Err(CodecError::Truncated {
                expected,
                received,
                part,
            }) => {
                assert_eq!(expected, 4);
                assert_eq!(received, 2);
                assert_eq!(part, "length prefix");
            }
            other => panic!("expected truncation, got {other:?}"),
        }
    }

    #[test]
    fn a_close_inside_the_body_is_truncation() {
        let framed =
            encode_message(&dict(&[("Request", "QueryType")]), PlistFormat::Binary).unwrap();
        let mut cut = &framed[..framed.len() - 3];
        match read_message(&mut cut) {
            Err(CodecError::Truncated { part, .. }) => assert_eq!(part, "body"),
            other => panic!("expected truncation, got {other:?}"),
        }
    }

    #[test]
    fn an_oversized_prefix_is_refused_before_anything_is_allocated() {
        let mut announced = Vec::from((MAX_MESSAGE_LEN as u32 + 1).to_be_bytes());
        announced.truncate(LENGTH_PREFIX_LEN);
        match read_message(&mut &announced[..]) {
            Err(CodecError::MessageTooLarge { announced }) => {
                assert_eq!(announced, MAX_MESSAGE_LEN as u64 + 1)
            }
            other => panic!("expected a size refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_length_prefix_is_refused_rather_than_silently_skipped() {
        let zero = 0u32.to_be_bytes();
        match read_message(&mut &zero[..]) {
            Err(CodecError::EmptyMessage) => {}
            other => panic!("expected an empty-message refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_writer_that_accepts_one_byte_at_a_time_still_receives_the_whole_frame() {
        let value = dict(&[("Request", "Reboot")]);
        let mut writer = OneByteWriter {
            written: Vec::new(),
        };
        let count = write_message(&mut writer, &value, PlistFormat::Binary).unwrap();
        assert_eq!(count, writer.written.len());
        assert_eq!(
            read_message(&mut &writer.written[..]).unwrap().unwrap(),
            value
        );
    }

    struct ChunkWriter {
        chunks: Vec<Vec<u8>>,
    }

    impl Write for ChunkWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.chunks.push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_ticket_sized_reply_is_one_length_prefixed_write() {
        let value = dict(&[("RootTicketData", "x")]);
        let mut writer = ChunkWriter { chunks: Vec::new() };
        write_message(&mut writer, &value, PlistFormat::Binary).unwrap();
        assert_eq!(
            writer.chunks[0].len(),
            encode_message(&value, PlistFormat::Binary).unwrap().len(),
            "a small body travels with its prefix in one write"
        );
    }

    #[test]
    fn a_nor_sized_body_travels_with_its_prefix_in_one_write() {
        let mut body = Dictionary::new();
        body.insert(
            "RestoreSEPImageData".to_string(),
            Value::Data(vec![0xAB; 0x8000 + 1]),
        );
        let value = Value::Dictionary(body);
        let mut writer = ChunkWriter { chunks: Vec::new() };
        write_message(&mut writer, &value, PlistFormat::Binary).unwrap();
        assert_eq!(
            writer.chunks.len(),
            1,
            "a peer reading the prefix with its own read-fully loop must never observe a frame cut between prefix and body"
        );
        let framed = &writer.chunks[0];
        assert_eq!(
            framed.len(),
            encode_message(&value, PlistFormat::Binary).unwrap().len()
        );
        let announced =
            u32::from_be_bytes(framed[..LENGTH_PREFIX_LEN].try_into().unwrap()) as usize;
        assert_eq!(announced, framed.len() - LENGTH_PREFIX_LEN);
        assert_eq!(
            read_message(&mut framed.as_slice()).unwrap().unwrap(),
            value
        );
    }

    #[test]
    fn an_integer_survives_the_round_trip_as_an_integer() {
        let mut body = Dictionary::new();
        body.insert("DataPort".to_string(), Value::Integer(Integer::from(12345)));
        let value = Value::Dictionary(body);
        let framed = encode_message(&value, PlistFormat::Binary).unwrap();
        let decoded = read_message(&mut &framed[..]).unwrap().unwrap();
        assert_eq!(
            decoded
                .as_dictionary()
                .unwrap()
                .get("DataPort")
                .unwrap()
                .as_signed_integer(),
            Some(12345)
        );
    }

    #[test]
    fn a_nor_sized_binary_plist_is_accepted_by_the_system_parser() {
        let mut body = Dictionary::new();
        body.insert(
            "RestoreSEPImageData".to_string(),
            Value::Data(vec![0xABu8; 5_873_222]),
        );
        body.insert(
            "SEPImageData".to_string(),
            Value::Data(vec![0xCDu8; 5_873_222]),
        );
        body.insert(
            "LlbImageData".to_string(),
            Value::Data(vec![0x11u8; 723_710]),
        );
        let mut named = Dictionary::new();
        named.insert("ANS".to_string(), Value::Data(vec![0x22u8; 976_178]));
        named.insert("iBoot".to_string(), Value::Data(vec![0x44u8; 562_442]));
        body.insert("NorImageData".to_string(), Value::Dictionary(named));
        let framed = encode_message(&Value::Dictionary(body), PlistFormat::Binary).unwrap();
        let plist = &framed[LENGTH_PREFIX_LEN..];
        assert!(plist.starts_with(b"bplist00"));
        let trailer = &plist[plist.len() - 32..];
        let offset_int_size = trailer[6];
        let offset_table = u64::from_be_bytes(trailer[24..32].try_into().unwrap());
        assert!(
            offset_int_size >= 4,
            "a 14 MiB NOR reply needs at least 4-byte offsets, trailer offsetIntSize={offset_int_size} offsetTable={offset_table}"
        );
        let decoded = Value::from_reader(std::io::Cursor::new(plist))
            .expect("a NOR-sized binary plist must decode with 4-byte offsets");
        let decoded = decoded
            .as_dictionary()
            .expect("the NOR-sized reply decodes to a dictionary");
        assert_eq!(
            decoded
                .get("RestoreSEPImageData")
                .and_then(Value::as_data)
                .map(<[u8]>::len),
            Some(5_873_222),
        );
        let nor = decoded
            .get("NorImageData")
            .and_then(Value::as_dictionary)
            .expect("NorImageData survives as a nested dictionary");
        assert_eq!(
            nor.get("iBoot").and_then(Value::as_data).map(<[u8]>::len),
            Some(562_442),
        );
    }

    #[test]
    fn binary_data_survives_the_round_trip_byte_for_byte() {
        let ticket: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let mut body = Dictionary::new();
        body.insert("RootTicketData".to_string(), Value::Data(ticket.clone()));
        let value = Value::Dictionary(body);
        let framed = encode_message(&value, PlistFormat::Binary).unwrap();
        let decoded = read_message(&mut &framed[..]).unwrap().unwrap();
        assert_eq!(
            decoded
                .as_dictionary()
                .unwrap()
                .get("RootTicketData")
                .unwrap()
                .as_data()
                .unwrap(),
            &ticket[..]
        );
    }
}
