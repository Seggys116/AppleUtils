use plist::{Dictionary, Integer, Value};

use super::codec::{Request, dict_integer};
use super::digest::ChecksumType;

pub const PROTOCOL_VERSION: i64 = 1;

pub const DEFAULT_PACKET_PAYLOAD_SIZE: i64 = 1450;

pub const DEFAULT_PACKETS_PER_FEC: i64 = 25;

pub const DEFAULT_FEC_SLICE_STRIDE: i64 = 40;

pub const DEFAULT_MAX_RETRY: i64 = 0x10_0000;

pub const KEY_VERSION: &str = "Version";
pub const KEY_PAYLOAD: &str = "Payload";
pub const KEY_METADATA: &str = "Metadata";
pub const KEY_STREAM_ID: &str = "Stream ID";
pub const KEY_PACKET_PAYLOAD_SIZE: &str = "Packet Payload Size";
pub const KEY_PACKETS_PER_FEC: &str = "Packets Per FEC";
pub const KEY_FEC_SLICE_STRIDE: &str = "FEC Slice Stride";
pub const KEY_MAX_RETRY: &str = "Max Retry";
pub const KEY_UUID: &str = "UUID";
pub const KEY_IMAGE_NAME: &str = "Image Name";
pub const KEY_DNS_SD_STATUS: &str = "DNS Service Discovery Status";
pub const KEY_CHECKSUM_CHUNKS: &str = "Checksum Chunks";
pub const KEY_CHECKSUM_CHUNK_SIZE: &str = "Checksum Chunk Size";
pub const KEY_CHECKSUM_TYPE: &str = "Checksum Type";

pub const KEY_SIZE: &str = "Size";
pub const KEY_PORT: &str = "Port";
pub const KEY_FAMILY: &str = "Family";
pub const KEY_ADDRESS: &str = "Address";
pub const KEY_CHECKSUM: &str = "Checksum";

pub const KEY_OOB_OFFSET: &str = "OOB Offset";
pub const KEY_OOB_LENGTH: &str = "OOB Length";
pub const KEY_OOB_RANGES: &str = "OOB Ranges";
pub const KEY_OOB_CHUNK: &str = "OOB Chunk";
pub const KEY_OOB_ERROR: &str = "OOB Error";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InitiateRequest {
    pub wants_checksum_chunks: bool,
    pub preferred_checksum_type: Option<ChecksumType>,
    pub image_name: Option<String>,
}

impl InitiateRequest {
    pub fn from_request(request: &Request) -> Self {
        let wants_checksum_chunks = request
            .body
            .get(KEY_CHECKSUM_CHUNKS)
            .and_then(Value::as_boolean)
            .unwrap_or(false);
        let preferred_checksum_type =
            dict_integer(&request.body, KEY_CHECKSUM_TYPE).and_then(ChecksumType::from_wire);
        let image_name = request
            .body
            .get(KEY_IMAGE_NAME)
            .and_then(Value::as_string)
            .map(str::to_string);
        Self {
            wants_checksum_chunks,
            preferred_checksum_type,
            image_name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamDescriptor {
    // asr reads `Stream ID`, `Port` and `Size` with no presence check: omitting one is a null deref.
    pub size: i64,
    pub port: i64,
    // Omitting `Family` and `Address` is what keeps the payload on the control connection.
    pub family: Option<i64>,
    pub address: Option<String>,
    pub checksum: Option<Vec<u8>>,
}

impl StreamDescriptor {
    pub fn on_control_connection(size: i64) -> Self {
        Self {
            size,
            port: 0,
            family: None,
            address: None,
            checksum: None,
        }
    }

    pub fn with_checksum(mut self, checksum: Vec<u8>) -> Self {
        self.checksum = Some(checksum);
        self
    }

    pub fn diverts_transport(&self) -> bool {
        self.family.is_some_and(|family| family != 0) && self.address.is_some()
    }

    pub fn to_value(&self) -> Value {
        let mut dict = Dictionary::new();
        if let Some(family) = self.family {
            dict.insert(
                KEY_FAMILY.to_string(),
                Value::Integer(Integer::from(family)),
            );
        }
        dict.insert(
            KEY_PORT.to_string(),
            Value::Integer(Integer::from(self.port)),
        );
        dict.insert(
            KEY_SIZE.to_string(),
            Value::Integer(Integer::from(self.size)),
        );
        if let Some(checksum) = &self.checksum {
            dict.insert(KEY_CHECKSUM.to_string(), Value::Data(checksum.clone()));
        }
        if let Some(address) = &self.address {
            dict.insert(KEY_ADDRESS.to_string(), Value::String(address.clone()));
        }
        Value::Dictionary(dict)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiateResponse {
    pub version: i64,
    pub payload: StreamDescriptor,
    pub metadata: Option<StreamDescriptor>,
    pub stream_id: i64,
    pub packet_payload_size: i64,
    pub packets_per_fec: i64,
    pub fec_slice_stride: i64,
    pub max_retry: i64,
    // asr reads these back only if it sent `Checksum Chunks`; unasked-for digests desync the stream.
    pub checksum_chunk_size: Option<i64>,
    pub checksum_type: Option<ChecksumType>,
    pub uuid: Option<String>,
    pub image_name: Option<String>,
    pub dns_service_discovery: Option<bool>,
}

impl InitiateResponse {
    pub fn new(payload: StreamDescriptor, stream_id: i64) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            payload,
            metadata: None,
            stream_id,
            packet_payload_size: DEFAULT_PACKET_PAYLOAD_SIZE,
            packets_per_fec: DEFAULT_PACKETS_PER_FEC,
            fec_slice_stride: DEFAULT_FEC_SLICE_STRIDE,
            max_retry: DEFAULT_MAX_RETRY,
            checksum_chunk_size: None,
            checksum_type: None,
            uuid: None,
            image_name: None,
            dns_service_discovery: None,
        }
    }

    pub fn effective_chunk_size(&self) -> u64 {
        match self.checksum_chunk_size {
            Some(size) if size > 0 => size as u64,
            _ => 0,
        }
    }

    pub fn effective_checksum_type(&self) -> ChecksumType {
        self.checksum_type.unwrap_or(ChecksumType::Sha256)
    }

    pub fn to_value(&self) -> Value {
        let mut dict = Dictionary::new();
        dict.insert(
            KEY_VERSION.to_string(),
            Value::Integer(Integer::from(self.version)),
        );
        dict.insert(KEY_PAYLOAD.to_string(), self.payload.to_value());
        if let Some(metadata) = &self.metadata {
            dict.insert(KEY_METADATA.to_string(), metadata.to_value());
        }
        dict.insert(
            KEY_STREAM_ID.to_string(),
            Value::Integer(Integer::from(self.stream_id)),
        );
        dict.insert(
            KEY_PACKET_PAYLOAD_SIZE.to_string(),
            Value::Integer(Integer::from(self.packet_payload_size)),
        );
        dict.insert(
            KEY_PACKETS_PER_FEC.to_string(),
            Value::Integer(Integer::from(self.packets_per_fec)),
        );
        dict.insert(
            KEY_FEC_SLICE_STRIDE.to_string(),
            Value::Integer(Integer::from(self.fec_slice_stride)),
        );
        dict.insert(
            KEY_MAX_RETRY.to_string(),
            Value::Integer(Integer::from(self.max_retry)),
        );
        if let Some(size) = self.checksum_chunk_size {
            dict.insert(
                KEY_CHECKSUM_CHUNK_SIZE.to_string(),
                Value::Integer(Integer::from(size)),
            );
            dict.insert(
                KEY_CHECKSUM_TYPE.to_string(),
                Value::Integer(Integer::from(self.effective_checksum_type().wire_value())),
            );
        }
        if let Some(uuid) = &self.uuid {
            dict.insert(KEY_UUID.to_string(), Value::String(uuid.clone()));
        }
        if let Some(name) = &self.image_name {
            dict.insert(KEY_IMAGE_NAME.to_string(), Value::String(name.clone()));
        }
        if let Some(status) = self.dns_service_discovery {
            dict.insert(KEY_DNS_SD_STATUS.to_string(), Value::Boolean(status));
        }
        Value::Dictionary(dict)
    }
}

#[cfg(test)]
mod tests {
    use super::super::codec::{Command, PlistReader, encode_plist};
    use super::*;

    #[test]
    fn a_bare_initiate_request_asks_for_nothing() {
        let request = Request::new(Command::Initiate);
        let parsed = InitiateRequest::from_request(&request);
        assert_eq!(parsed, InitiateRequest::default());
        assert!(!parsed.wants_checksum_chunks);
    }

    #[test]
    fn an_initiate_request_carrying_checksum_chunks_is_read_as_a_request_for_them() {
        let mut request = Request::new(Command::Initiate);
        request
            .body
            .insert(KEY_CHECKSUM_CHUNKS.to_string(), Value::Boolean(true));
        request.body.insert(
            KEY_CHECKSUM_TYPE.to_string(),
            Value::Integer(Integer::from(1)),
        );
        request.body.insert(
            KEY_IMAGE_NAME.to_string(),
            Value::String("Default.dmg".to_string()),
        );

        let parsed = InitiateRequest::from_request(&request);
        assert!(parsed.wants_checksum_chunks);
        assert_eq!(parsed.preferred_checksum_type, Some(ChecksumType::Sha256));
        assert_eq!(parsed.image_name.as_deref(), Some("Default.dmg"));
    }

    #[test]
    fn a_checksum_type_asr_would_refuse_is_not_carried_forward() {
        let mut request = Request::new(Command::Initiate);
        request.body.insert(
            KEY_CHECKSUM_TYPE.to_string(),
            Value::Integer(Integer::from(2)),
        );
        assert_eq!(
            InitiateRequest::from_request(&request).preferred_checksum_type,
            None
        );
    }

    #[test]
    fn a_control_connection_descriptor_carries_size_and_port_and_no_address() {
        let descriptor = StreamDescriptor::on_control_connection(13_071_548_416);
        assert!(!descriptor.diverts_transport());
        let dict = descriptor.to_value();
        let dict = dict.as_dictionary().unwrap();
        assert_eq!(
            dict.get(KEY_SIZE).unwrap().as_signed_integer(),
            Some(13_071_548_416)
        );
        assert!(dict.contains_key(KEY_PORT));
        assert!(!dict.contains_key(KEY_FAMILY));
        assert!(!dict.contains_key(KEY_ADDRESS));
    }

    #[test]
    fn a_descriptor_naming_a_family_and_address_is_flagged_as_diverting() {
        let mut descriptor = StreamDescriptor::on_control_connection(64);
        descriptor.family = Some(30);
        descriptor.address = Some("::1".to_string());
        assert!(descriptor.diverts_transport());
    }

    #[test]
    fn the_initiate_response_carries_every_key_asr_reads_without_a_presence_check() {
        let response = InitiateResponse::new(StreamDescriptor::on_control_connection(4096), 0x1234);
        let value = response.to_value();
        let dict = value.as_dictionary().unwrap();

        assert_eq!(dict.get(KEY_VERSION).unwrap().as_signed_integer(), Some(1));
        assert!(dict.contains_key(KEY_STREAM_ID));
        assert_eq!(
            dict.get(KEY_PACKET_PAYLOAD_SIZE)
                .unwrap()
                .as_signed_integer(),
            Some(1450)
        );
        assert_eq!(
            dict.get(KEY_PACKETS_PER_FEC).unwrap().as_signed_integer(),
            Some(25)
        );
        assert_eq!(
            dict.get(KEY_FEC_SLICE_STRIDE).unwrap().as_signed_integer(),
            Some(40)
        );
        assert_eq!(
            dict.get(KEY_MAX_RETRY).unwrap().as_signed_integer(),
            Some(0x10_0000)
        );

        let payload = dict.get(KEY_PAYLOAD).unwrap().as_dictionary().unwrap();
        assert!(payload.contains_key(KEY_SIZE));
        assert!(payload.contains_key(KEY_PORT));

        assert!(!dict.contains_key(KEY_CHECKSUM_CHUNK_SIZE));
        assert!(!dict.contains_key(KEY_CHECKSUM_TYPE));
        assert!(!dict.contains_key(KEY_METADATA));
    }

    #[test]
    fn offering_chunk_checksums_adds_both_keys_together() {
        let mut response = InitiateResponse::new(StreamDescriptor::on_control_connection(4096), 1);
        response.checksum_chunk_size = Some(0x10_0000);
        response.checksum_type = Some(ChecksumType::Sha256);
        let value = response.to_value();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict.get(KEY_CHECKSUM_CHUNK_SIZE)
                .unwrap()
                .as_signed_integer(),
            Some(0x10_0000)
        );
        assert_eq!(
            dict.get(KEY_CHECKSUM_TYPE).unwrap().as_signed_integer(),
            Some(1)
        );
        assert_eq!(response.effective_chunk_size(), 0x10_0000);
    }

    #[test]
    fn the_initiate_response_survives_a_round_trip_through_the_wire_form() {
        let mut response = InitiateResponse::new(StreamDescriptor::on_control_connection(1024), 7);
        response.metadata =
            Some(StreamDescriptor::on_control_connection(320).with_checksum(vec![0xab; 20]));
        response.uuid = Some("A2B4C6D8-0000-1111-2222-333344445555".to_string());
        response.image_name = Some("OS.dmg".to_string());
        response.dns_service_discovery = Some(false);

        let bytes = encode_plist(&response.to_value()).unwrap();
        let mut reader = PlistReader::new(std::io::Cursor::new(bytes));
        let decoded = reader.read_value().unwrap().unwrap();
        assert_eq!(decoded, response.to_value());

        let dict = decoded.as_dictionary().unwrap().clone();
        let metadata = dict.get(KEY_METADATA).unwrap().as_dictionary().unwrap();
        assert_eq!(
            metadata.get(KEY_CHECKSUM).unwrap().as_data(),
            Some(&[0xabu8; 20][..])
        );
        assert_eq!(
            dict.get(KEY_DNS_SD_STATUS).unwrap().as_boolean(),
            Some(false)
        );
    }
}
