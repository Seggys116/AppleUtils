use std::fmt;

use plist::{Dictionary, Integer, Value};

pub const KEY_REQUEST: &str = "Request";
pub const KEY_MSG_TYPE: &str = "MsgType";

pub const SERVICE_TYPE: &str = "com.apple.mobile.restored";

pub const PROTOCOL_MUX_SOCKET: &str = "MuxSocket";

pub const KEY_TYPE: &str = "Type";
pub const KEY_RESTORE_PROTOCOL_VERSION: &str = "RestoreProtocolVersion";
pub const KEY_RESULT: &str = "Result";
pub const RESULT_SUCCESS: &str = "Success";
pub const KEY_QUERY_KEY: &str = "QueryKey";
pub const KEY_QUERY_VALUE: &str = "QueryValue";
pub const KEY_RESTORE_OPTIONS: &str = "RestoreOptions";
pub const KEY_SUPPORTED_HOST_PROTOCOLS: &str = "SupportedHostProtocols";

pub const KEY_DATA_TYPE: &str = "DataType";
pub const KEY_DATA_PORT: &str = "DataPort";
pub const KEY_ARGUMENTS: &str = "Arguments";
pub const KEY_ASYNC_CONTEXT_UUID: &str = "AsyncContextUUID";
pub const KEY_OPERATION: &str = "Operation";
pub const KEY_PROGRESS: &str = "Progress";
pub const KEY_STATUS: &str = "Status";
pub const KEY_AM_R_ERROR: &str = "AMRError";
pub const KEY_SUCCESSFUL: &str = "Successful";
pub const KEY_LOG: &str = "Log";
pub const KEY_CHECKPOINT_STATS: &str = "Checkpoint Stats";

pub const KEY_CHECKPOINT_ID: &str = "CHECKPOINT_ID";
pub const KEY_CHECKPOINT_NAME: &str = "CHECKPOINT_NAME";
pub const KEY_CHECKPOINT_RESULT: &str = "CHECKPOINT_RESULT";
pub const KEY_CHECKPOINT_COMPLETE: &str = "CHECKPOINT_COMPLETE";
pub const KEY_CHECKPOINT_ERROR: &str = "CHECKPOINT_ERROR";
pub const KEY_CHECKPOINT_WARNING: &str = "CHECKPOINT_WARNING";
pub const KEY_CHECKPOINT_INFO: &str = "CHECKPOINT_INFO";

pub const KEY_CRASH_LOG_FILENAME: &str = "Filename";

pub const KEY_CRASH_LOG_DATA: &str = "Data";

pub const KEY_WILL_SEND_EOF: &str = "WillSendEOF";

/// Never `SystemImageType`: the guest reads no such key, so the misspelling is silently ignored.
pub const KEY_SYSTEM_IMAGE_FORMAT: &str = "SystemImageFormat";

pub const KEY_VARIANT: &str = "Variant";
pub const KEY_BUILD_IDENTITY_DICT: &str = "BuildIdentityDict";
pub const KEY_ROOT_TICKET_DATA: &str = "RootTicketData";

pub const KEY_FILE_DATA: &str = "FileData";

pub const KEY_FILE_DATA_DONE: &str = "FileDataDone";

pub const KEY_DATA_SIZE: &str = "DataSize";

pub const KEY_DATA_CHUNK_SIZE: &str = "DataChunkSize";

pub const KEY_IMAGE_NAME: &str = "ImageName";

pub const KEY_IMAGE_LIST: &str = "ImageList";

pub const KEY_IMAGE_TYPE: &str = "ImageType";

pub const KEY_IS_RECOVERY_OS: &str = "IsRecoveryOS";

pub const KEY_GLOBAL_MANIFEST_PREFIX: &str = "GlobalManifestPrefix";

pub const KEY_GLOBAL_MANIFEST_OPTIONAL: &str = "GlobalManifestOptional";

pub const IMAGE_NAME_GLOBAL_MANIFEST: &str = "__GlobalManifest__";

pub const IMAGE_NAME_RESTORE_VERSION: &str = "__RestoreVersion__";
pub const IMAGE_NAME_SYSTEM_VERSION: &str = "__SystemVersion__";

pub const RESTORE_VERSION_FILE_NAME: &str = "RestoreVersion.plist";
pub const SYSTEM_VERSION_FILE_NAME: &str = "SystemVersion.plist";

#[must_use]
pub fn streamed_object_messages(bytes: &[u8], chunk_size: usize) -> Vec<Dictionary> {
    let mut messages = Vec::new();
    for chunk in bytes.chunks(streamed_stride(bytes.len() as u64, chunk_size)) {
        let first = messages.is_empty();
        messages.push(streamed_chunk_message(
            chunk,
            first.then_some(bytes.len() as u64),
        ));
    }
    messages.push(streamed_done_message(messages.is_empty()));
    messages
}

#[must_use]
pub fn streamed_stride(total_len: u64, chunk_size: usize) -> usize {
    if chunk_size == 0 {
        usize::try_from(total_len).unwrap_or(usize::MAX).max(1)
    } else {
        chunk_size
    }
}

#[must_use]
pub fn streamed_chunk_message(chunk: &[u8], total_len: Option<u64>) -> Dictionary {
    let mut message = Dictionary::new();
    if let Some(total) = total_len {
        message.insert(
            KEY_DATA_SIZE.to_string(),
            Value::Integer(plist::Integer::from(total)),
        );
    }
    message.insert(KEY_FILE_DATA.to_string(), Value::Data(chunk.to_vec()));
    message
}

#[must_use]
pub fn streamed_done_message(carries_size: bool) -> Dictionary {
    let mut done = Dictionary::new();
    if carries_size {
        done.insert(
            KEY_DATA_SIZE.to_string(),
            Value::Integer(plist::Integer::from(0u64)),
        );
    }
    done.insert(KEY_FILE_DATA_DONE.to_string(), Value::Boolean(true));
    done
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Request {
    QueryType,
    QueryValue,
    StartRestore,
    Reboot,
    Goodbye,
}

impl Request {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::QueryType => "QueryType",
            Self::QueryValue => "QueryValue",
            Self::StartRestore => "StartRestore",
            Self::Reboot => "Reboot",
            Self::Goodbye => "Goodbye",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "QueryType" => Some(Self::QueryType),
            "QueryValue" => Some(Self::QueryValue),
            "StartRestore" => Some(Self::StartRestore),
            "Reboot" => Some(Self::Reboot),
            "Goodbye" => Some(Self::Goodbye),
            _ => None,
        }
    }

    pub fn to_value(self) -> Value {
        let mut body = Dictionary::new();
        body.insert(
            KEY_REQUEST.to_string(),
            Value::String(self.wire_name().to_string()),
        );
        Value::Dictionary(body)
    }
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QueryKey {
    SerialNumber,
    Imei,
    HardwareInfo,
    HardwareModel,
    Logs,
    SavedDebugInfo,
    SystemPartitionSize,
    StartRestore,
}

impl QueryKey {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SerialNumber => "SerialNumber",
            Self::Imei => "IMEI",
            Self::HardwareInfo => "HardwareInfo",
            Self::HardwareModel => "HardwareModel",
            Self::Logs => "Logs",
            Self::SavedDebugInfo => "SavedDebugInfo",
            Self::SystemPartitionSize => "SystemPartitionSize",
            Self::StartRestore => "StartRestore",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "SerialNumber" => Some(Self::SerialNumber),
            "IMEI" => Some(Self::Imei),
            "HardwareInfo" => Some(Self::HardwareInfo),
            "HardwareModel" => Some(Self::HardwareModel),
            "Logs" => Some(Self::Logs),
            "SavedDebugInfo" => Some(Self::SavedDebugInfo),
            "SystemPartitionSize" => Some(Self::SystemPartitionSize),
            "StartRestore" => Some(Self::StartRestore),
            _ => None,
        }
    }
}

impl fmt::Display for QueryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum MsgType {
    DataRequestMsg,
    AsyncDataRequestMsg,
    AsyncWait,
    ProgressMsg,
    StatusMsg,
    CheckpointMsg,
    PreviousRestoreLogMsg,
    ReceivedFinalStatusMsg,
    RestoredCrash,
    CrashLog,
    RestoreAttestation,
    BBUpdateStatusMsg,
    ProvisioningStatusMsg,
    Other(String),
}

impl MsgType {
    pub fn wire_name(&self) -> &str {
        match self {
            Self::DataRequestMsg => "DataRequestMsg",
            Self::AsyncDataRequestMsg => "AsyncDataRequestMsg",
            Self::AsyncWait => "AsyncWait",
            Self::ProgressMsg => "ProgressMsg",
            Self::StatusMsg => "StatusMsg",
            Self::CheckpointMsg => "CheckpointMsg",
            Self::PreviousRestoreLogMsg => "PreviousRestoreLogMsg",
            Self::ReceivedFinalStatusMsg => "ReceivedFinalStatusMsg",
            Self::RestoredCrash => "RestoredCrash",
            Self::CrashLog => "CrashLog",
            Self::RestoreAttestation => "RestoreAttestation",
            Self::BBUpdateStatusMsg => "BBUpdateStatusMsg",
            Self::ProvisioningStatusMsg => "ProvisioningStatusMsg",
            Self::Other(name) => name,
        }
    }

    pub fn from_wire(name: &str) -> Self {
        match name {
            "DataRequestMsg" => Self::DataRequestMsg,
            "AsyncDataRequestMsg" => Self::AsyncDataRequestMsg,
            "AsyncWait" => Self::AsyncWait,
            "ProgressMsg" => Self::ProgressMsg,
            "StatusMsg" => Self::StatusMsg,
            "CheckpointMsg" => Self::CheckpointMsg,
            "PreviousRestoreLogMsg" => Self::PreviousRestoreLogMsg,
            "ReceivedFinalStatusMsg" => Self::ReceivedFinalStatusMsg,
            "RestoredCrash" => Self::RestoredCrash,
            "CrashLog" => Self::CrashLog,
            "RestoreAttestation" => Self::RestoreAttestation,
            "BBUpdateStatusMsg" => Self::BBUpdateStatusMsg,
            "ProvisioningStatusMsg" => Self::ProvisioningStatusMsg,
            other => Self::Other(other.to_string()),
        }
    }

    pub fn expects_answer(&self) -> bool {
        matches!(self, Self::DataRequestMsg | Self::AsyncDataRequestMsg)
    }
}

impl fmt::Display for MsgType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

pub fn final_status_acknowledgement() -> Value {
    let mut body = Dictionary::new();
    body.insert(
        KEY_MSG_TYPE.to_string(),
        Value::String(MsgType::ReceivedFinalStatusMsg.wire_name().to_string()),
    );
    Value::Dictionary(body)
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DataType {
    RootTicket,
    RootTicketData,
    ApTicket,
    RecoveryOSRootTicketData,
    BuildIdentityDict,
    BuildIdentityDictV2,
    RecoveryOSASRImage,
    RecoveryOSLocalPolicy,
    RecoveryOSVersionData,
    SourceBootObjectV3,
    SourceBootObjectV4,
    SourceBootObjectV5,
    PersonalizedBootObjectV3,
    SystemImageData,
    /// Declared but fetched as `PersonalizedBootObjectV3` with `ImageName` `SystemVolume`.
    /// Must be a full `IMG4` wrapped with the board manifest, not the bare `IM4P` on disk.
    SystemImageRootHash,
    /// Declared but fetched as `Ap,SystemVolumeCanonicalMetadata`.
    SystemImageCanonicalMetadata,
    Other(String),
}

impl DataType {
    pub fn wire_name(&self) -> &str {
        match self {
            Self::RootTicket => "RootTicket",
            Self::RootTicketData => "RootTicketData",
            Self::ApTicket => "APTicket",
            Self::RecoveryOSRootTicketData => "RecoveryOSRootTicketData",
            Self::BuildIdentityDict => "BuildIdentityDict",
            Self::BuildIdentityDictV2 => "BuildIdentityDictV2",
            Self::RecoveryOSASRImage => "RecoveryOSASRImage",
            Self::RecoveryOSLocalPolicy => "RecoveryOSLocalPolicy",
            Self::RecoveryOSVersionData => "RecoveryOSVersionData",
            Self::SourceBootObjectV3 => "SourceBootObjectV3",
            Self::SourceBootObjectV4 => "SourceBootObjectV4",
            Self::SourceBootObjectV5 => "SourceBootObjectV5",
            Self::PersonalizedBootObjectV3 => "PersonalizedBootObjectV3",
            Self::SystemImageData => "SystemImageData",
            Self::SystemImageRootHash => "SystemImageRootHash",
            Self::SystemImageCanonicalMetadata => "SystemImageCanonicalMetadata",
            Self::Other(name) => name,
        }
    }

    pub fn from_wire(name: &str) -> Self {
        match name {
            "RootTicket" => Self::RootTicket,
            "RootTicketData" => Self::RootTicketData,
            "APTicket" => Self::ApTicket,
            "RecoveryOSRootTicketData" => Self::RecoveryOSRootTicketData,
            "BuildIdentityDict" => Self::BuildIdentityDict,
            "BuildIdentityDictV2" => Self::BuildIdentityDictV2,
            "RecoveryOSASRImage" => Self::RecoveryOSASRImage,
            "RecoveryOSLocalPolicy" => Self::RecoveryOSLocalPolicy,
            "RecoveryOSVersionData" => Self::RecoveryOSVersionData,
            "SourceBootObjectV3" => Self::SourceBootObjectV3,
            "SourceBootObjectV4" => Self::SourceBootObjectV4,
            "SourceBootObjectV5" => Self::SourceBootObjectV5,
            "PersonalizedBootObjectV3" => Self::PersonalizedBootObjectV3,
            "SystemImageData" => Self::SystemImageData,
            "SystemImageRootHash" => Self::SystemImageRootHash,
            "SystemImageCanonicalMetadata" => Self::SystemImageCanonicalMetadata,
            other => Self::Other(other.to_string()),
        }
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SystemImageFormat {
    DiskImage,
    AeaWrappedDiskImage,
}

impl SystemImageFormat {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::DiskImage => "DiskImage",
            Self::AeaWrappedDiskImage => "AEAWrappedDiskImage",
        }
    }

    pub fn from_wire(name: &str) -> Option<Self> {
        match name {
            "DiskImage" => Some(Self::DiskImage),
            "AEAWrappedDiskImage" => Some(Self::AeaWrappedDiskImage),
            _ => None,
        }
    }

    pub const fn supports_async_delivery(self) -> bool {
        matches!(self, Self::DiskImage)
    }
}

impl fmt::Display for SystemImageFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RestoreOptions {
    protocols: Vec<String>,
    extra: Dictionary,
}

impl RestoreOptions {
    pub fn new() -> Self {
        Self {
            protocols: vec![PROTOCOL_MUX_SOCKET.to_string()],
            extra: Dictionary::new(),
        }
    }

    pub fn with_protocol(mut self, protocol: &str) -> Self {
        if !self.protocols.iter().any(|known| known == protocol) {
            self.protocols.push(protocol.to_string());
        }
        self
    }

    pub fn with_system_image_format(self, format: SystemImageFormat) -> Self {
        self.with_value(
            KEY_SYSTEM_IMAGE_FORMAT,
            Value::String(format.wire_name().to_string()),
        )
    }

    pub fn with_value(mut self, key: &str, value: Value) -> Self {
        self.extra.insert(key.to_string(), value);
        self
    }

    pub fn with_flag(self, key: &str, value: bool) -> Self {
        self.with_value(key, Value::Boolean(value))
    }

    pub fn with_integer(self, key: &str, value: i64) -> Self {
        self.with_value(key, Value::Integer(Integer::from(value)))
    }

    pub fn system_image_format(&self) -> Option<SystemImageFormat> {
        self.extra
            .get(KEY_SYSTEM_IMAGE_FORMAT)
            .and_then(Value::as_string)
            .and_then(SystemImageFormat::from_wire)
    }

    pub fn integer_value(&self, key: &str) -> Option<i64> {
        self.extra.get(key).and_then(Value::as_signed_integer)
    }

    pub fn into_value(self) -> Result<Value, OptionsError> {
        if !self
            .protocols
            .iter()
            .any(|protocol| protocol == PROTOCOL_MUX_SOCKET)
        {
            return Err(OptionsError::MissingMuxSocket);
        }
        let mut options = self.extra;
        options.insert(
            KEY_SUPPORTED_HOST_PROTOCOLS.to_string(),
            Value::Array(self.protocols.into_iter().map(Value::String).collect()),
        );
        Ok(Value::Dictionary(options))
    }
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptionsError {
    MissingMuxSocket,
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMuxSocket => write!(
                f,
                "RestoreOptions.{KEY_SUPPORTED_HOST_PROTOCOLS} must contain {PROTOCOL_MUX_SOCKET}"
            ),
        }
    }
}

impl std::error::Error for OptionsError {}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceType {
    pub service_type: String,
    pub protocol_version: Option<i64>,
    pub body: Dictionary,
}

impl DeviceType {
    pub fn is_restored(&self) -> bool {
        self.service_type == SERVICE_TYPE
    }

    pub fn string(&self, key: &str) -> Option<&str> {
        self.body.get(key).and_then(Value::as_string)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeviceMessage {
    pub msg_type: MsgType,
    pub body: Dictionary,
}

impl DeviceMessage {
    pub fn from_value(value: &Value) -> Option<Self> {
        let body = value.as_dictionary()?;
        let name = body.get(KEY_MSG_TYPE).and_then(Value::as_string)?;
        Some(Self {
            msg_type: MsgType::from_wire(name),
            body: body.clone(),
        })
    }

    pub fn as_data_request(&self) -> Option<DataRequest> {
        if !self.msg_type.expects_answer() {
            return None;
        }
        let data_type = self
            .body
            .get(KEY_DATA_TYPE)
            .and_then(Value::as_string)
            .map(DataType::from_wire)?;
        let data_port = self
            .body
            .get(KEY_DATA_PORT)
            .and_then(Value::as_signed_integer)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0);
        let arguments = self
            .body
            .get(KEY_ARGUMENTS)
            .and_then(Value::as_dictionary)
            .cloned()
            .unwrap_or_default();
        Some(DataRequest {
            data_type,
            data_port,
            arguments,
            asynchronous: self.msg_type == MsgType::AsyncDataRequestMsg,
            async_context_uuid: self
                .body
                .get(KEY_ASYNC_CONTEXT_UUID)
                .and_then(Value::as_string)
                .map(str::to_string),
        })
    }

    pub fn async_context_uuid(&self) -> Option<&str> {
        self.body
            .get(KEY_ASYNC_CONTEXT_UUID)
            .and_then(Value::as_string)
    }

    pub fn as_progress(&self) -> Option<Progress> {
        if self.msg_type != MsgType::ProgressMsg {
            return None;
        }
        Some(Progress {
            operation: self
                .body
                .get(KEY_OPERATION)
                .and_then(Value::as_signed_integer),
            fraction: self.body.get(KEY_PROGRESS).and_then(numeric),
        })
    }

    pub fn as_checkpoint(&self) -> Option<Checkpoint<'_>> {
        if self.msg_type != MsgType::CheckpointMsg {
            return None;
        }
        Some(Checkpoint {
            id: self
                .body
                .get(KEY_CHECKPOINT_ID)
                .and_then(Value::as_signed_integer),
            name: self
                .body
                .get(KEY_CHECKPOINT_NAME)
                .and_then(Value::as_string),
            result: self
                .body
                .get(KEY_CHECKPOINT_RESULT)
                .and_then(Value::as_signed_integer),
            complete: self
                .body
                .get(KEY_CHECKPOINT_COMPLETE)
                .and_then(Value::as_boolean),
            has_error: self.body.contains_key(KEY_CHECKPOINT_ERROR),
            has_warning: self.body.contains_key(KEY_CHECKPOINT_WARNING),
            has_info: self.body.contains_key(KEY_CHECKPOINT_INFO),
        })
    }

    pub fn as_crash_log(&self) -> Option<CrashLog<'_>> {
        if self.msg_type != MsgType::CrashLog {
            return None;
        }
        Some(CrashLog {
            filename: self
                .body
                .get(KEY_CRASH_LOG_FILENAME)
                .and_then(Value::as_string),
            data: self.body.get(KEY_CRASH_LOG_DATA).and_then(Value::as_data),
        })
    }

    pub fn as_status(&self) -> Option<i64> {
        if self.msg_type != MsgType::StatusMsg {
            return None;
        }
        self.body.get(KEY_STATUS).and_then(Value::as_signed_integer)
    }

    pub fn as_final_status(&self) -> Option<FinalStatus> {
        if self.msg_type != MsgType::StatusMsg {
            return None;
        }
        Some(FinalStatus {
            status: self.body.get(KEY_STATUS).and_then(Value::as_signed_integer),
            amr_error: self
                .body
                .get(KEY_AM_R_ERROR)
                .and_then(Value::as_signed_integer),
            successful: self.body.get(KEY_SUCCESSFUL).and_then(Value::as_boolean),
            will_send_eof: self.body.get(KEY_WILL_SEND_EOF).and_then(Value::as_boolean),
            has_checkpoint_stats: self.body.contains_key(KEY_CHECKPOINT_STATS),
            has_log: self.body.contains_key(KEY_LOG),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalStatus {
    pub status: Option<i64>,
    pub amr_error: Option<i64>,
    pub successful: Option<bool>,
    pub will_send_eof: Option<bool>,
    pub has_checkpoint_stats: bool,
    pub has_log: bool,
}

impl FinalStatus {
    pub fn succeeded(&self) -> bool {
        self.successful == Some(true)
    }

    pub fn outcome(&self) -> &'static str {
        match self.successful {
            Some(true) => "successful",
            Some(false) => "failed",
            None => "unreadable",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Progress {
    pub operation: Option<i64>,
    pub fraction: Option<f64>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Checkpoint<'a> {
    pub id: Option<i64>,
    pub name: Option<&'a str>,
    pub result: Option<i64>,
    pub complete: Option<bool>,
    pub has_error: bool,
    pub has_warning: bool,
    pub has_info: bool,
}

impl Checkpoint<'_> {
    pub fn id_display(&self) -> String {
        self.id
            .map_or_else(|| "none".to_string(), |id| format!("0x{id:04X}"))
    }

    pub fn ends_step(&self) -> bool {
        self.complete == Some(true)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrashLog<'a> {
    pub filename: Option<&'a str>,
    pub data: Option<&'a [u8]>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DataRequest {
    pub data_type: DataType,
    pub data_port: Option<u16>,
    pub arguments: Dictionary,
    pub asynchronous: bool,
    pub async_context_uuid: Option<String>,
}

impl DataRequest {
    pub fn argument_string(&self, key: &str) -> Option<&str> {
        self.arguments.get(key).and_then(Value::as_string)
    }

    pub fn argument_bool(&self, key: &str) -> Option<bool> {
        self.arguments.get(key).and_then(Value::as_boolean)
    }

    pub fn argument_integer(&self, key: &str) -> Option<i64> {
        self.arguments.get(key).and_then(Value::as_signed_integer)
    }

    pub fn is_bulk_transfer(&self) -> bool {
        self.data_port.is_some()
    }
}

fn numeric(value: &Value) -> Option<f64> {
    if let Some(real) = value.as_real() {
        return Some(real);
    }
    value.as_signed_integer().map(|integer| integer as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_incremental_framing_matches_the_all_at_once_framing() {
        let bytes: Vec<u8> = (0u8..=255).cycle().take(1000).collect();
        for chunk_size in [0usize, 1, 7, 256, 1000, 4096] {
            let expected = streamed_object_messages(&bytes, chunk_size);
            let stride = streamed_stride(bytes.len() as u64, chunk_size);
            let mut built = Vec::new();
            for chunk in bytes.chunks(stride) {
                let first = built.is_empty();
                built.push(streamed_chunk_message(
                    chunk,
                    first.then_some(bytes.len() as u64),
                ));
            }
            built.push(streamed_done_message(built.is_empty()));
            assert_eq!(built, expected, "chunk_size={chunk_size}");
        }
    }

    #[test]
    fn a_streamed_object_carries_the_size_once_and_ends_with_the_flag() {
        let messages = streamed_object_messages(&[1, 2, 3, 4, 5], 2);
        assert_eq!(messages.len(), 4);
        assert_eq!(
            messages[0]
                .get(KEY_DATA_SIZE)
                .and_then(Value::as_signed_integer),
            Some(5)
        );
        assert_eq!(
            messages[0].get(KEY_FILE_DATA).and_then(Value::as_data),
            Some(&[1u8, 2][..])
        );
        for message in &messages[1..3] {
            assert!(message.get(KEY_DATA_SIZE).is_none());
            assert!(message.get(KEY_FILE_DATA).is_some());
            assert!(message.get(KEY_FILE_DATA_DONE).is_none());
        }
        assert_eq!(
            messages[3]
                .get(KEY_FILE_DATA_DONE)
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert!(messages[3].get(KEY_FILE_DATA).is_none());
    }

    #[test]
    fn a_zero_length_object_is_one_complete_message() {
        let messages = streamed_object_messages(&[], 131_072);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0]
                .get(KEY_DATA_SIZE)
                .and_then(Value::as_signed_integer),
            Some(0)
        );
        assert_eq!(
            messages[0]
                .get(KEY_FILE_DATA_DONE)
                .and_then(Value::as_boolean),
            Some(true)
        );
    }

    fn device_message(pairs: Vec<(&str, Value)>) -> Value {
        let mut body = Dictionary::new();
        for (key, value) in pairs {
            body.insert(key.to_string(), value);
        }
        Value::Dictionary(body)
    }

    #[test]
    fn a_streamed_object_is_framed_as_sized_chunks_ended_by_the_done_flag() {
        let messages = streamed_object_messages(&[1, 2, 3, 4, 5], 2);
        assert_eq!(messages.len(), 4);
        assert_eq!(
            messages[0]
                .get(KEY_DATA_SIZE)
                .and_then(Value::as_unsigned_integer),
            Some(5)
        );
        assert_eq!(
            messages[0].get(KEY_FILE_DATA).and_then(Value::as_data),
            Some([1, 2].as_slice())
        );
        assert!(!messages[1].contains_key(KEY_DATA_SIZE));
        assert_eq!(
            messages[1].get(KEY_FILE_DATA).and_then(Value::as_data),
            Some([3, 4].as_slice())
        );
        assert_eq!(
            messages[2].get(KEY_FILE_DATA).and_then(Value::as_data),
            Some([5].as_slice())
        );
        assert_eq!(
            messages[3]
                .get(KEY_FILE_DATA_DONE)
                .and_then(Value::as_boolean),
            Some(true)
        );
        assert!(!messages[3].contains_key(KEY_FILE_DATA));
    }

    #[test]
    fn an_empty_streamed_object_is_one_message_that_ends_the_stream() {
        let messages = streamed_object_messages(&[], 4096);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0]
                .get(KEY_DATA_SIZE)
                .and_then(Value::as_unsigned_integer),
            Some(0)
        );
        assert_eq!(
            messages[0]
                .get(KEY_FILE_DATA_DONE)
                .and_then(Value::as_boolean),
            Some(true)
        );
    }

    #[test]
    fn an_unstated_chunk_size_sends_the_object_in_one_chunk() {
        let messages = streamed_object_messages(&[7; 9], 0);
        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].get(KEY_FILE_DATA).and_then(Value::as_data),
            Some([7; 9].as_slice())
        );
    }

    #[test]
    fn the_final_status_acknowledgement_is_the_one_message_the_guest_accepts() {
        let value = final_status_acknowledgement();
        let body = value.as_dictionary().expect("a dictionary");
        assert_eq!(
            body.get(KEY_MSG_TYPE).and_then(Value::as_string),
            Some("ReceivedFinalStatusMsg")
        );
        assert!(body.get(KEY_WILL_SEND_EOF).is_none());
        assert_eq!(body.len(), 1);
        assert_eq!(
            DeviceMessage::from_value(&value).map(|message| message.msg_type),
            Some(MsgType::ReceivedFinalStatusMsg)
        );
        assert!(body.get(KEY_REQUEST).is_none());
    }

    #[test]
    fn the_final_status_reading_takes_the_criterion_from_successful_and_not_from_the_code() {
        let succeeded = device_message(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".to_string())),
            (KEY_STATUS, Value::Integer(0.into())),
            (KEY_AM_R_ERROR, Value::Integer(0.into())),
            (KEY_SUCCESSFUL, Value::Boolean(true)),
            (KEY_WILL_SEND_EOF, Value::Boolean(true)),
            (KEY_CHECKPOINT_STATS, Value::String(String::new())),
        ]);
        let reading = DeviceMessage::from_value(&succeeded)
            .and_then(|message| message.as_final_status())
            .expect("a StatusMsg reads as a final status");
        assert!(reading.succeeded());
        assert_eq!(reading.outcome(), "successful");
        assert_eq!(reading.status, Some(0));
        assert_eq!(reading.amr_error, Some(0));
        assert!(reading.has_checkpoint_stats);
        assert!(!reading.has_log);

        let failed = device_message(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".to_string())),
            (KEY_STATUS, Value::Integer(31.into())),
            (KEY_SUCCESSFUL, Value::Boolean(false)),
            (KEY_LOG, Value::String("...".to_string())),
        ]);
        let reading = DeviceMessage::from_value(&failed)
            .and_then(|message| message.as_final_status())
            .expect("a StatusMsg reads as a final status");
        assert!(!reading.succeeded());
        assert_eq!(reading.outcome(), "failed");
        assert!(reading.has_log);

        let unreadable = device_message(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".to_string())),
            (KEY_STATUS, Value::Integer(0.into())),
        ]);
        let reading = DeviceMessage::from_value(&unreadable)
            .and_then(|message| message.as_final_status())
            .expect("a StatusMsg reads as a final status even with keys absent");
        assert!(!reading.succeeded());
        assert_eq!(reading.outcome(), "unreadable");
        assert_eq!(reading.successful, None);

        let checkpoint = device_message(vec![(
            KEY_MSG_TYPE,
            Value::String("CheckpointMsg".to_string()),
        )]);
        assert!(
            DeviceMessage::from_value(&checkpoint)
                .and_then(|message| message.as_final_status())
                .is_none()
        );
    }

    #[test]
    fn every_request_name_round_trips_through_the_wire_spelling() {
        for request in [
            Request::QueryType,
            Request::QueryValue,
            Request::StartRestore,
            Request::Reboot,
            Request::Goodbye,
        ] {
            assert_eq!(Request::from_wire(request.wire_name()), Some(request));
        }
    }

    #[test]
    fn an_unknown_request_name_does_not_decode() {
        assert_eq!(Request::from_wire("StartRestoreV2"), None);
        assert_eq!(Request::from_wire("startrestore"), None);
    }

    #[test]
    fn a_request_value_carries_the_request_key_and_nothing_else() {
        let value = Request::QueryType.to_value();
        let body = value.as_dictionary().unwrap();
        assert_eq!(body.len(), 1);
        assert_eq!(
            body.get(KEY_REQUEST).unwrap().as_string(),
            Some("QueryType")
        );
    }

    #[test]
    fn options_carry_mux_socket_without_the_caller_asking() {
        let value = RestoreOptions::new().into_value().unwrap();
        let protocols = value
            .as_dictionary()
            .unwrap()
            .get(KEY_SUPPORTED_HOST_PROTOCOLS)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(protocols.len(), 1);
        assert_eq!(protocols[0].as_string(), Some(PROTOCOL_MUX_SOCKET));
    }

    #[test]
    fn an_extra_protocol_is_added_beside_mux_socket_not_instead_of_it() {
        let value = RestoreOptions::new()
            .with_protocol("SomethingElse")
            .into_value()
            .unwrap();
        let protocols: Vec<_> = value
            .as_dictionary()
            .unwrap()
            .get(KEY_SUPPORTED_HOST_PROTOCOLS)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry.as_string().unwrap().to_string())
            .collect();
        assert_eq!(protocols, vec!["MuxSocket", "SomethingElse"]);
    }

    #[test]
    fn asking_for_mux_socket_twice_does_not_list_it_twice() {
        let value = RestoreOptions::new()
            .with_protocol(PROTOCOL_MUX_SOCKET)
            .into_value()
            .unwrap();
        let protocols = value
            .as_dictionary()
            .unwrap()
            .get(KEY_SUPPORTED_HOST_PROTOCOLS)
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(protocols.len(), 1);
    }

    #[test]
    fn the_image_format_setter_writes_the_key_the_guest_actually_reads() {
        let value = RestoreOptions::new()
            .with_system_image_format(SystemImageFormat::DiskImage)
            .into_value()
            .unwrap();
        let options = value.as_dictionary().unwrap();
        assert_eq!(
            options.get("SystemImageFormat").unwrap().as_string(),
            Some("DiskImage")
        );
        assert!(
            !options.contains_key("SystemImageType"),
            "SystemImageType is the trap spelling and must never be emitted"
        );
    }

    #[test]
    fn the_aea_format_is_marked_as_refusing_asynchronous_delivery() {
        assert!(SystemImageFormat::DiskImage.supports_async_delivery());
        assert!(!SystemImageFormat::AeaWrappedDiskImage.supports_async_delivery());
    }

    #[test]
    fn a_data_request_decodes_its_type_port_and_arguments() {
        let mut arguments = Dictionary::new();
        arguments.insert("ImageName".to_string(), Value::String("kernel".into()));
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("RecoveryOSASRImage".into())),
            (KEY_DATA_PORT, Value::Integer(Integer::from(12345))),
            (KEY_ARGUMENTS, Value::Dictionary(arguments)),
        ]))
        .unwrap();
        let request = message.as_data_request().unwrap();
        assert_eq!(request.data_type, DataType::RecoveryOSASRImage);
        assert_eq!(request.data_port, Some(12345));
        assert!(request.is_bulk_transfer());
        assert!(!request.asynchronous);
        assert_eq!(request.argument_string("ImageName"), Some("kernel"));
    }

    #[test]
    fn a_data_request_without_a_port_is_answered_on_the_control_connection() {
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("BuildIdentityDict".into())),
        ]))
        .unwrap();
        let request = message.as_data_request().unwrap();
        assert_eq!(request.data_type, DataType::BuildIdentityDict);
        assert_eq!(request.data_port, None);
        assert!(!request.is_bulk_transfer());
        assert!(request.arguments.is_empty());
    }

    #[test]
    fn an_async_data_request_is_flagged_as_asynchronous() {
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("AsyncDataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("SourceBootObjectV4".into())),
        ]))
        .unwrap();
        let request = message.as_data_request().unwrap();
        assert!(request.asynchronous);
        assert_eq!(request.data_type, DataType::SourceBootObjectV4);
    }

    #[test]
    fn a_port_outside_the_sixteen_bit_range_is_dropped_rather_than_truncated() {
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("RecoveryOSASRImage".into())),
            (KEY_DATA_PORT, Value::Integer(Integer::from(65536 + 12345))),
        ]))
        .unwrap();
        assert_eq!(message.as_data_request().unwrap().data_port, None);
    }

    #[test]
    fn a_zero_port_is_dropped_because_nothing_listens_there() {
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("RecoveryOSASRImage".into())),
            (KEY_DATA_PORT, Value::Integer(Integer::from(0))),
        ]))
        .unwrap();
        assert_eq!(message.as_data_request().unwrap().data_port, None);
    }

    #[test]
    fn an_unmodelled_message_type_keeps_its_name_instead_of_being_dropped() {
        let message = DeviceMessage::from_value(&device_message(vec![(
            KEY_MSG_TYPE,
            Value::String("SomeFutureMsg".into()),
        )]))
        .unwrap();
        assert_eq!(message.msg_type, MsgType::Other("SomeFutureMsg".into()));
        assert!(!message.msg_type.expects_answer());
        assert_eq!(message.msg_type.wire_name(), "SomeFutureMsg");
    }

    #[test]
    fn an_unmodelled_data_type_keeps_its_name() {
        let message = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("DataRequestMsg".into())),
            (KEY_DATA_TYPE, Value::String("FirmwareUpdaterData".into())),
        ]))
        .unwrap();
        assert_eq!(
            message.as_data_request().unwrap().data_type,
            DataType::Other("FirmwareUpdaterData".into())
        );
    }

    #[test]
    fn only_the_two_data_request_types_expect_an_answer() {
        assert!(MsgType::DataRequestMsg.expects_answer());
        assert!(MsgType::AsyncDataRequestMsg.expects_answer());
        for quiet in [
            MsgType::ProgressMsg,
            MsgType::StatusMsg,
            MsgType::CheckpointMsg,
            MsgType::AsyncWait,
            MsgType::PreviousRestoreLogMsg,
            MsgType::ReceivedFinalStatusMsg,
            MsgType::RestoredCrash,
            MsgType::RestoreAttestation,
            MsgType::BBUpdateStatusMsg,
            MsgType::ProvisioningStatusMsg,
        ] {
            assert!(!quiet.expects_answer(), "{quiet} must not be answered");
        }
    }

    #[test]
    fn progress_reads_both_the_integer_and_the_real_encoding() {
        let integral = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("ProgressMsg".into())),
            (KEY_OPERATION, Value::Integer(Integer::from(28))),
            (KEY_PROGRESS, Value::Integer(Integer::from(42))),
        ]))
        .unwrap()
        .as_progress()
        .unwrap();
        assert_eq!(integral.operation, Some(28));
        assert_eq!(integral.fraction, Some(42.0));

        let fractional = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("ProgressMsg".into())),
            (KEY_PROGRESS, Value::Real(0.5)),
        ]))
        .unwrap()
        .as_progress()
        .unwrap();
        assert_eq!(fractional.fraction, Some(0.5));
        assert_eq!(fractional.operation, None);
    }

    #[test]
    fn a_message_without_a_msgtype_does_not_decode_as_one() {
        assert!(
            DeviceMessage::from_value(&device_message(vec![(
                KEY_REQUEST,
                Value::String("QueryType".into())
            )]))
            .is_none()
        );
        assert!(DeviceMessage::from_value(&Value::String("not a dict".into())).is_none());
    }

    #[test]
    fn a_progress_accessor_refuses_a_message_that_is_not_a_progress_message() {
        let status = DeviceMessage::from_value(&device_message(vec![
            (KEY_MSG_TYPE, Value::String("StatusMsg".into())),
            (KEY_STATUS, Value::Integer(Integer::from(0))),
        ]))
        .unwrap();
        assert!(status.as_progress().is_none());
        assert_eq!(status.as_status(), Some(0));
        assert!(status.as_data_request().is_none());
    }

    #[test]
    fn every_query_key_round_trips() {
        for key in [
            QueryKey::SerialNumber,
            QueryKey::Imei,
            QueryKey::HardwareInfo,
            QueryKey::HardwareModel,
            QueryKey::Logs,
            QueryKey::SavedDebugInfo,
            QueryKey::SystemPartitionSize,
            QueryKey::StartRestore,
        ] {
            assert_eq!(QueryKey::from_wire(key.wire_name()), Some(key));
        }
        assert_eq!(QueryKey::Imei.wire_name(), "IMEI");
    }

    #[test]
    fn every_modelled_data_type_round_trips() {
        for data_type in [
            DataType::RootTicket,
            DataType::RootTicketData,
            DataType::ApTicket,
            DataType::RecoveryOSRootTicketData,
            DataType::BuildIdentityDict,
            DataType::BuildIdentityDictV2,
            DataType::RecoveryOSASRImage,
            DataType::RecoveryOSLocalPolicy,
            DataType::SourceBootObjectV3,
            DataType::SourceBootObjectV4,
            DataType::SourceBootObjectV5,
            DataType::PersonalizedBootObjectV3,
        ] {
            assert_eq!(DataType::from_wire(data_type.wire_name()), data_type);
        }
        assert_eq!(DataType::ApTicket.wire_name(), "APTicket");
    }
}
