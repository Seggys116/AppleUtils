use std::fmt;
use std::io::{self, Read, Write};

use plist::{Dictionary, Integer, Value};

pub const READ_CHUNK_LEN: usize = 0x400;

pub const MAX_REQUEST_LEN: usize = 4 * 1024 * 1024;

const PLIST_CLOSE_TAG: &[u8] = b"</plist>";

pub const KEY_COMMAND: &str = "Command";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Initiate,
    Metadata,
    OobData,
    Payload,
}

impl Command {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Initiate => "Initiate",
            Self::Metadata => "Metadata",
            Self::OobData => "OOBData",
            Self::Payload => "Payload",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "Initiate" => Some(Self::Initiate),
            "Metadata" => Some(Self::Metadata),
            "OOBData" => Some(Self::OobData),
            "Payload" => Some(Self::Payload),
            _ => None,
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Request {
    pub command: Command,
    pub body: Dictionary,
}

impl Request {
    pub fn new(command: Command) -> Self {
        let mut body = Dictionary::new();
        body.insert(
            KEY_COMMAND.to_string(),
            Value::String(command.wire_name().to_string()),
        );
        Self { command, body }
    }

    pub fn with_integer(mut self, key: &str, value: i64) -> Self {
        self.body
            .insert(key.to_string(), Value::Integer(Integer::from(value)));
        self
    }

    pub fn from_value(value: &Value) -> Result<Self, CodecError> {
        let body = value
            .as_dictionary()
            .ok_or(CodecError::MalformedRequest("request is not a dictionary"))?;
        let name = body.get(KEY_COMMAND).and_then(Value::as_string).ok_or(
            CodecError::MalformedRequest("request has no Command string"),
        )?;
        let command =
            Command::from_wire(name).ok_or_else(|| CodecError::UnknownCommand(name.to_string()))?;
        Ok(Self {
            command,
            body: body.clone(),
        })
    }

    pub fn to_value(&self) -> Value {
        Value::Dictionary(self.body.clone())
    }

    pub fn integer(&self, key: &str) -> Option<i64> {
        dict_integer(&self.body, key)
    }
}

pub fn dict_integer(dict: &Dictionary, key: &str) -> Option<i64> {
    dict.get(key)?.as_signed_integer()
}

pub fn encode_plist(value: &Value) -> Result<Vec<u8>, CodecError> {
    let mut bytes = Vec::new();
    value.to_writer_xml(&mut bytes)?;
    Ok(bytes)
}

// One plist, no terminator or padding: asr re-parses its read buffer, so any extra byte hangs it.
pub fn write_plist<W: Write>(out: &mut W, value: &Value) -> Result<(), CodecError> {
    let bytes = encode_plist(value)?;
    out.write_all(&bytes)?;
    out.flush()?;
    Ok(())
}

pub struct PlistReader<R> {
    inner: R,
    pending: Vec<u8>,
}

impl<R: Read> PlistReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            pending: Vec::new(),
        }
    }

    pub fn pending(&self) -> &[u8] {
        &self.pending
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }

    pub fn read_value(&mut self) -> Result<Option<Value>, CodecError> {
        loop {
            if let Some(end) = find_close_tag(&self.pending) {
                let document: Vec<u8> = self.pending.drain(..end).collect();
                let value = Value::from_reader_xml(io::Cursor::new(document))?;
                return Ok(Some(value));
            }
            if self.pending.len() > MAX_REQUEST_LEN {
                return Err(CodecError::RequestTooLarge(self.pending.len()));
            }
            let mut chunk = [0u8; READ_CHUNK_LEN];
            let read = self.inner.read(&mut chunk)?;
            if read == 0 {
                if self.pending.iter().all(u8::is_ascii_whitespace) {
                    self.pending.clear();
                    return Ok(None);
                }
                return Err(CodecError::Truncated(self.pending.len()));
            }
            self.pending.extend_from_slice(&chunk[..read]);
        }
    }

    pub fn read_request(&mut self) -> Result<Option<Request>, CodecError> {
        match self.read_value()? {
            Some(value) => Ok(Some(Request::from_value(&value)?)),
            None => Ok(None),
        }
    }
}

fn find_close_tag(buf: &[u8]) -> Option<usize> {
    if buf.len() < PLIST_CLOSE_TAG.len() {
        return None;
    }
    buf.windows(PLIST_CLOSE_TAG.len())
        .position(|window| window == PLIST_CLOSE_TAG)
        .map(|start| start + PLIST_CLOSE_TAG.len())
}

#[derive(Debug)]
pub enum CodecError {
    Io(io::Error),
    Plist(plist::Error),
    MalformedRequest(&'static str),
    UnknownCommand(String),
    Truncated(usize),
    RequestTooLarge(usize),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Plist(err) => write!(f, "{err}"),
            Self::MalformedRequest(reason) => write!(f, "malformed request: {reason}"),
            Self::UnknownCommand(name) => write!(f, "unknown command {name:?}"),
            Self::Truncated(len) => {
                write!(f, "peer closed after {len} bytes of an unterminated plist")
            }
            Self::RequestTooLarge(len) => {
                write!(f, "request grew past {len} bytes without closing")
            }
        }
    }
}

impl std::error::Error for CodecError {}

impl From<io::Error> for CodecError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<plist::Error> for CodecError {
    fn from(err: plist::Error) -> Self {
        Self::Plist(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml(value: &Value) -> Vec<u8> {
        encode_plist(value).unwrap()
    }

    #[test]
    fn command_names_round_trip_through_the_wire_spelling() {
        for command in [
            Command::Initiate,
            Command::Metadata,
            Command::OobData,
            Command::Payload,
        ] {
            assert_eq!(Command::from_wire(command.wire_name()), Some(command));
        }
        assert_eq!(Command::from_wire("OOBdata"), None);
        assert_eq!(Command::OobData.wire_name(), "OOBData");
    }

    #[test]
    fn a_serialised_response_is_exactly_one_plist_with_nothing_after_it() {
        let mut dict = Dictionary::new();
        dict.insert("Version".to_string(), Value::Integer(Integer::from(1)));
        let bytes = xml(&Value::Dictionary(dict));

        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(text.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""));
        assert!(text.ends_with("</plist>"));
        assert_eq!(find_close_tag(&bytes), Some(bytes.len()));
        assert_eq!(text.matches("</plist>").count(), 1);
    }

    #[test]
    fn requests_round_trip_through_the_codec() {
        let request = Request::new(Command::OobData)
            .with_integer("OOB Offset", 0)
            .with_integer("OOB Length", 64);
        let bytes = xml(&request.to_value());
        let mut reader = PlistReader::new(io::Cursor::new(bytes));
        let decoded = reader.read_request().unwrap().unwrap();
        assert_eq!(decoded.command, Command::OobData);
        assert_eq!(decoded.integer("OOB Offset"), Some(0));
        assert_eq!(decoded.integer("OOB Length"), Some(64));
        assert_eq!(decoded, request);
        assert!(reader.read_request().unwrap().is_none());
    }

    #[test]
    fn a_request_split_across_reads_is_reassembled() {
        struct DribbleReader {
            bytes: Vec<u8>,
            position: usize,
        }
        impl Read for DribbleReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.position >= self.bytes.len() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.bytes[self.position];
                self.position += 1;
                Ok(1)
            }
        }

        let request = Request::new(Command::Initiate);
        let mut reader = PlistReader::new(DribbleReader {
            bytes: xml(&request.to_value()),
            position: 0,
        });
        let decoded = reader.read_request().unwrap().unwrap();
        assert_eq!(decoded.command, Command::Initiate);
    }

    #[test]
    fn two_coalesced_requests_are_read_in_order() {
        let mut bytes = xml(&Request::new(Command::Initiate).to_value());
        bytes.extend_from_slice(&xml(&Request::new(Command::Payload).to_value()));

        let mut reader = PlistReader::new(io::Cursor::new(bytes));
        assert_eq!(
            reader.read_request().unwrap().unwrap().command,
            Command::Initiate
        );
        assert_eq!(
            reader.read_request().unwrap().unwrap().command,
            Command::Payload
        );
        assert!(reader.read_request().unwrap().is_none());
    }

    #[test]
    fn a_truncated_request_is_an_error_not_a_clean_end() {
        let mut bytes = xml(&Request::new(Command::Initiate).to_value());
        bytes.truncate(bytes.len() - 4);
        let mut reader = PlistReader::new(io::Cursor::new(bytes));
        assert!(matches!(
            reader.read_request(),
            Err(CodecError::Truncated(_))
        ));
    }

    #[test]
    fn an_unknown_command_is_rejected_by_name() {
        let mut dict = Dictionary::new();
        dict.insert(KEY_COMMAND.to_string(), Value::String("Rewind".to_string()));
        let bytes = xml(&Value::Dictionary(dict));
        let mut reader = PlistReader::new(io::Cursor::new(bytes));
        match reader.read_request() {
            Err(CodecError::UnknownCommand(name)) => assert_eq!(name, "Rewind"),
            other => panic!("expected UnknownCommand, got {other:?}"),
        }
    }

    #[test]
    fn a_document_without_a_command_key_is_malformed() {
        let bytes = xml(&Value::Dictionary(Dictionary::new()));
        let mut reader = PlistReader::new(io::Cursor::new(bytes));
        assert!(matches!(
            reader.read_request(),
            Err(CodecError::MalformedRequest(_))
        ));
    }
}
