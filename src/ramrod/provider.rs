use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;

use plist::{Dictionary, Value};

use super::message::{Checkpoint, DataRequest, DataType, FinalStatus};
use crate::restore::thread_class::ThreadClass;

pub trait RestoreDataProvider {
    fn supply(&mut self, request: &DataRequest) -> Result<Dictionary, ProviderError>;

    fn supply_streamed(
        &mut self,
        _request: &DataRequest,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StreamedObject {
    pub payload: StreamedPayload,
    pub chunk_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StreamedPayload {
    Bytes(Vec<u8>),
    File { path: PathBuf, len: u64 },
}

impl StreamedObject {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>, chunk_size: usize) -> Self {
        Self {
            payload: StreamedPayload::Bytes(bytes),
            chunk_size,
        }
    }

    pub fn from_file(path: PathBuf, chunk_size: usize) -> std::io::Result<Self> {
        let len = std::fs::metadata(&path)?.len();
        Ok(Self {
            payload: StreamedPayload::File { path, len },
            chunk_size,
        })
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        match &self.payload {
            StreamedPayload::Bytes(bytes) => bytes.len() as u64,
            StreamedPayload::File { len, .. } => *len,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BulkOutcome {
    Served {
        bytes: u64,
        blocks: u64,
        initiates: u32,
        metadata_requests: u32,
        oob_requests: u32,
        oob_bytes: u64,
    },
    Declined {
        reason: String,
    },
}

pub trait BulkTransferService {
    fn serve(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError>;
}

pub trait SessionObserver {
    fn on_stream_thread_class(&mut self, _request: &DataRequest, _class: ThreadClass) {}
    fn on_progress(&mut self, _operation: Option<i64>, _fraction: Option<f64>) {}
    fn on_status(&mut self, _status: i64, _body: &Dictionary) {}
    fn on_final_status(&mut self, _status: &FinalStatus, _body: &Dictionary) {}
    fn on_final_status_acknowledged(&mut self, _status: Option<i64>, _bytes: usize) {}
    fn on_checkpoint(&mut self, _checkpoint: &Checkpoint<'_>, _body: &Dictionary) {}
    fn on_crash_log(
        &mut self,
        _filename: &str,
        _bytes: usize,
        _path: Option<&std::path::Path>,
        _error: Option<&str>,
    ) {
    }
    fn on_message(&mut self, _msg_type: &str, _body: &Dictionary) {}
    fn on_data_request(&mut self, _request: &DataRequest) {}
    fn on_bulk_serving(&mut self, _request: &DataRequest, _port: u16) {}
    fn on_data_answered(&mut self, _request: &DataRequest, _keys: &[&str], _bytes: usize) {}
    fn on_data_streamed(
        &mut self,
        _request: &DataRequest,
        _object_bytes: usize,
        _messages: usize,
        _framed_bytes: usize,
    ) {
    }
    fn on_bulk_served(&mut self, _request: &DataRequest, _port: u16, _outcome: &BulkOutcome) {}
    fn on_bulk_served_empty(&mut self, _request: &DataRequest, _port: u16, _outcome: &BulkOutcome) {
    }
    fn on_bulk_declined(&mut self, _request: &DataRequest, _port: u16, _reason: &str) {}
    fn on_async_wait(&mut self, _uuid: Option<&str>, _body: &Dictionary) {}
    fn on_data_unanswered(&mut self, _request: &DataRequest, _error: &ProviderError) {}
    fn on_control_send_failed(&mut self, _request: &DataRequest, _error: &str) {}
}

impl SessionObserver for () {}

#[derive(Clone, Debug, Default)]
pub struct PreparedAnswers {
    answers: HashMap<String, Dictionary>,
}

impl PreparedAnswers {
    pub fn new() -> Self {
        Self {
            answers: HashMap::new(),
        }
    }

    pub fn with(mut self, data_type: DataType, body: Dictionary) -> Self {
        self.answers.insert(data_type.wire_name().to_string(), body);
        self
    }

    pub fn with_key(self, data_type: DataType, key: &str, value: Value) -> Self {
        let mut body = Dictionary::new();
        body.insert(key.to_string(), value);
        self.with(data_type, body)
    }

    pub fn with_ticket(self, data_type: DataType, ticket: Vec<u8>) -> Self {
        self.with_key(
            data_type,
            super::message::KEY_ROOT_TICKET_DATA,
            Value::Data(ticket),
        )
    }

    pub fn with_build_identity(
        self,
        data_type: DataType,
        identity: Dictionary,
        variant: &str,
    ) -> Self {
        let mut body = Dictionary::new();
        body.insert(
            super::message::KEY_BUILD_IDENTITY_DICT.to_string(),
            Value::Dictionary(identity),
        );
        body.insert(
            super::message::KEY_VARIANT.to_string(),
            Value::String(variant.to_string()),
        );
        self.with(data_type, body)
    }

    pub fn covers(&self, data_type: &DataType) -> bool {
        self.answers.contains_key(data_type.wire_name())
    }

    pub fn len(&self) -> usize {
        self.answers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty()
    }
}

impl RestoreDataProvider for PreparedAnswers {
    fn supply(&mut self, request: &DataRequest) -> Result<Dictionary, ProviderError> {
        self.answers
            .get(request.data_type.wire_name())
            .cloned()
            .ok_or_else(|| ProviderError::Unsupported {
                data_type: request.data_type.wire_name().to_string(),
            })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoBulkTransfers;

impl BulkTransferService for NoBulkTransfers {
    fn serve(&mut self, port: u16, request: &DataRequest) -> Result<BulkOutcome, ProviderError> {
        Err(ProviderError::BulkTransferNotConfigured {
            port,
            data_type: request.data_type.wire_name().to_string(),
        })
    }
}

#[derive(Debug)]
pub enum ProviderError {
    Unsupported { data_type: String },
    BulkTransferNotConfigured { port: u16, data_type: String },
    Io(io::Error),
    Other(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { data_type } => {
                write!(f, "no answer is prepared for a {data_type} request")
            }
            Self::BulkTransferNotConfigured { port, data_type } => write!(
                f,
                "the guest opened port {port} for a {data_type} transfer and no bulk transfer service was configured"
            ),
            Self::Io(error) => write!(f, "{error}"),
            Self::Other(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for ProviderError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(data_type: DataType, port: Option<u16>) -> DataRequest {
        DataRequest {
            data_type,
            data_port: port,
            arguments: Dictionary::new(),
            asynchronous: false,
            async_context_uuid: None,
        }
    }

    #[test]
    fn a_prepared_ticket_comes_back_under_the_key_the_guest_reads() {
        let ticket = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let mut answers = PreparedAnswers::new().with_ticket(DataType::RootTicket, ticket.clone());
        let body = answers
            .supply(&request(DataType::RootTicket, None))
            .unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(
            body.get("RootTicketData").unwrap().as_data(),
            Some(&ticket[..])
        );
    }

    #[test]
    fn a_build_identity_answer_always_carries_the_variant_beside_it() {
        let mut identity = Dictionary::new();
        identity.insert("Ap,ProductType".to_string(), Value::String("J413AP".into()));
        let mut answers = PreparedAnswers::new().with_build_identity(
            DataType::BuildIdentityDict,
            identity,
            "Customer Erase Install (IPSW)",
        );
        let body = answers
            .supply(&request(DataType::BuildIdentityDict, None))
            .unwrap();
        assert!(
            body.get("BuildIdentityDict")
                .unwrap()
                .as_dictionary()
                .is_some()
        );
        assert_eq!(
            body.get("Variant").unwrap().as_string(),
            Some("Customer Erase Install (IPSW)")
        );
    }

    #[test]
    fn an_unprepared_type_is_refused_by_name_rather_than_answered_empty() {
        let mut answers = PreparedAnswers::new();
        match answers.supply(&request(DataType::SourceBootObjectV4, None)) {
            Err(ProviderError::Unsupported { data_type }) => {
                assert_eq!(data_type, "SourceBootObjectV4")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unmodelled_type_is_refused_under_its_own_wire_name() {
        let mut answers = PreparedAnswers::new();
        let asked = DataType::Other("FirmwareUpdaterData".into());
        match answers.supply(&request(asked, None)) {
            Err(ProviderError::Unsupported { data_type }) => {
                assert_eq!(data_type, "FirmwareUpdaterData")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn coverage_can_be_checked_before_a_session_starts() {
        let answers = PreparedAnswers::new()
            .with_ticket(DataType::RootTicket, vec![1, 2, 3])
            .with_ticket(DataType::RecoveryOSRootTicketData, vec![4, 5, 6]);
        assert_eq!(answers.len(), 2);
        assert!(!answers.is_empty());
        assert!(answers.covers(&DataType::RootTicket));
        assert!(answers.covers(&DataType::RecoveryOSRootTicketData));
        assert!(!answers.covers(&DataType::BuildIdentityDict));
    }

    #[test]
    fn the_refusing_bulk_service_names_the_port_and_the_type() {
        let mut service = NoBulkTransfers;
        match service.serve(12345, &request(DataType::RecoveryOSASRImage, Some(12345))) {
            Err(ProviderError::BulkTransferNotConfigured { port, data_type }) => {
                assert_eq!(port, 12345);
                assert_eq!(data_type, "RecoveryOSASRImage");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }
}
