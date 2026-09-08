use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::bridge_protocol::{FdrManifestSignature, MAX_SIGNED_BODY_BYTES, SignFdrManifestRequest};
use crate::crypto::{
    P256_SIGNATURE_BYTES, P256_UNCOMPRESSED_BYTES, P256PrivateKey, sha384, verify_uncompressed,
};

use crate::ramrod::fdr_manifest::{
    MANIFEST_BODY_DER_TAG, ManifestProperties, SealManifestError, SealObject,
    build_manifest_from_signed_body, encode_properties_only_body, encode_signed_body,
    random_server_nonce, signing_digest,
};
use crate::ramrod::fdr_object::{
    FdrObjectError, FdrTrustMaterial, SEALING_LEAF_SERIAL_FILE_NAME, load_or_generate_serial,
};
use crate::ramrod::fdr_pki::{
    CertificateIdentity, DEFAULT_LEAF_COMMON_NAME, DEFAULT_ORGANIZATION, DistinguishedName,
    issue_fdr_device_certificate, issue_fdr_leaf, random_serial,
};
use crate::ramrod::fdr_request::{SealingRequestError, parse_sealing_request};
use crate::ramrod::fdr_store::{DataResource, FdrDataStore, SEAL_CLASS};
use crate::ramrod::pem::{self, LABEL_CERTIFICATE, LABEL_CERTIFICATE_REQUEST, PemError};
use crate::ramrod::pkcs10::{self, Pkcs10Error};

use super::plan::hex_digest;
use super::report::{SharedReporter, report};

pub const FDR_SEAL_PREFIX: &str = "[fdr-seal]";

pub const FDR_SERVICE_ADDRESS: &str = "192.0.2.1";

pub const FDR_SERVICE_PORT: u16 = 8062;

pub const CA_AUTHORIZE_PATH: &str = "/ca/authorize";

pub const SEALING_SIGN_PREFIX: &str = "/sealing/sign/";

pub const DATA_STORE_PREFIX: &str = "/dm/data/";

pub const DATA_STORE_DIRECTORY: &str = "data-store";

pub const STATUS_NOT_FOUND: u16 = 404;

pub const SEAL_VERSION_HEADER: &str = "x-fdr-seal-version";

pub const SEAL_MANIFEST_VERSION_HEADER: &str = "x-fdr-seal-manifest-version";

pub const SEAL_DATA_VERSION: u32 = 2;

pub const CONTENT_TYPE_OCTET_STREAM: &str = "application/octet-stream";

pub const CONTENT_TYPE_PEM: &str = "application/x-pem-file";

pub const MAX_REQUEST_BODY: usize = 4 * 1024 * 1024;

const MAX_LINE: usize = 8 * 1024;

const MAX_HEADERS: usize = 128;

// What this BOOLEAN selects is not established, so `false`: if it gates a tolerance, `false` leaves the consuming side's checks running.
const MANIFEST_FAIC: bool = false;

pub const SIGNING_KEY_SOURCE_SEP: &str = "sep-identity-key";

pub const SIGNING_KEY_SOURCE_LEAF_SEED: &str = "sealing-leaf-seed";

pub const BRIDGE_SIGN_MANB_REQUEST: u16 = 21;

pub const BRIDGE_SIGN_MANB_RESPONSE: u16 = 22;

pub const BRIDGE_SIGN_MANB_RESPONSE_BYTES: usize = 185;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionReply {
    pub response_code: u16,
    pub body: Vec<u8>,
}

pub trait SessionBroker: Send + Sync {
    fn request(&self, request_code: u16, body: &[u8]) -> Result<SessionReply, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestSignerError {
    BodyTooLarge {
        length: usize,
        maximum: usize,
    },
    MissingExpectedPublicKey,
    Broker(String),
    UnexpectedResponseCode {
        expected: u16,
        actual: u16,
    },
    UnexpectedResponseLength {
        expected: usize,
        actual: usize,
    },
    UnexpectedSignedBodyLength {
        expected: u32,
        actual: u32,
    },
    // Boxed to keep `ManifestSignerError` under clippy's `result_large_err` threshold; nothing reads these fields.
    UnexpectedDigest {
        expected: Box<[u8; 48]>,
        actual: Box<[u8; 48]>,
    },
    UnexpectedPublicKey {
        expected: Box<[u8; P256_UNCOMPRESSED_BYTES]>,
        actual: Box<[u8; P256_UNCOMPRESSED_BYTES]>,
    },
    InvalidSignature,
}

impl std::fmt::Display for ManifestSignerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BodyTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "the MANB signed body is {length} bytes and the signer accepts at most {maximum}"
                )
            }
            Self::MissingExpectedPublicKey => {
                formatter.write_str("the restore context named remote MANB signing but no SEP public key")
            }
            Self::Broker(error) => formatter.write_str(error),
            Self::UnexpectedResponseCode { expected, actual } => {
                write!(
                    formatter,
                    "the remote signer replied with code {actual} where {expected} was required"
                )
            }
            Self::UnexpectedResponseLength { expected, actual } => {
                write!(
                    formatter,
                    "the remote signer replied with {actual} body bytes where {expected} were required"
                )
            }
            Self::UnexpectedSignedBodyLength { expected, actual } => {
                write!(
                    formatter,
                    "the remote signer echoed MANB length {actual} where {expected} was required"
                )
            }
            Self::UnexpectedDigest { .. } => formatter.write_str(
                "the remote signer replied with a SHA-384 that does not match the MANB body it was asked to sign",
            ),
            Self::UnexpectedPublicKey { .. } => formatter.write_str(
                "the remote signer replied under a different SEP public key from the one the restore context named",
            ),
            Self::InvalidSignature => formatter.write_str(
                "the remote signer returned a P-256 signature that does not verify over the leftmost 32 bytes of the MANB SHA-384",
            ),
        }
    }
}

impl std::error::Error for ManifestSignerError {}

pub trait FdrManifestSigner: Send + Sync {
    fn source(&self) -> &'static str;
    fn public_key(&self) -> [u8; P256_UNCOMPRESSED_BYTES];
    fn sign_manb_body(
        &self,
        signed_body: &[u8],
    ) -> Result<[u8; P256_SIGNATURE_BYTES], ManifestSignerError>;
}

#[derive(Clone, Copy, Debug)]
pub struct LocalFdrManifestSigner {
    key: P256PrivateKey,
    source: &'static str,
}

impl LocalFdrManifestSigner {
    #[must_use]
    pub fn new(key: P256PrivateKey, source: &'static str) -> Self {
        Self { key, source }
    }
}

impl FdrManifestSigner for LocalFdrManifestSigner {
    fn source(&self) -> &'static str {
        self.source
    }

    fn public_key(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        self.key.public_uncompressed()
    }

    fn sign_manb_body(
        &self,
        signed_body: &[u8],
    ) -> Result<[u8; P256_SIGNATURE_BYTES], ManifestSignerError> {
        let digest = sha384(signed_body);
        Ok(self.key.sign_digest(&signing_digest(&digest)))
    }
}

pub struct RemoteManifestSigner {
    broker: Arc<dyn SessionBroker>,
    expected_public_key: [u8; P256_UNCOMPRESSED_BYTES],
}

impl RemoteManifestSigner {
    #[must_use]
    pub fn new(
        broker: Arc<dyn SessionBroker>,
        expected_public_key: [u8; P256_UNCOMPRESSED_BYTES],
    ) -> Self {
        Self {
            broker,
            expected_public_key,
        }
    }
}

impl FdrManifestSigner for RemoteManifestSigner {
    fn source(&self) -> &'static str {
        SIGNING_KEY_SOURCE_SEP
    }

    fn public_key(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        self.expected_public_key
    }

    fn sign_manb_body(
        &self,
        signed_body: &[u8],
    ) -> Result<[u8; P256_SIGNATURE_BYTES], ManifestSignerError> {
        if signed_body.len() > MAX_SIGNED_BODY_BYTES {
            return Err(ManifestSignerError::BodyTooLarge {
                length: signed_body.len(),
                maximum: MAX_SIGNED_BODY_BYTES,
            });
        }

        let request_body = SignFdrManifestRequest {
            signed_body: signed_body.to_vec(),
        }
        .encode()
        .map_err(|error| ManifestSignerError::Broker(error.to_string()))?;

        let reply = self
            .broker
            .request(BRIDGE_SIGN_MANB_REQUEST, &request_body)
            .map_err(ManifestSignerError::Broker)?;
        if reply.response_code != BRIDGE_SIGN_MANB_RESPONSE {
            return Err(ManifestSignerError::UnexpectedResponseCode {
                expected: BRIDGE_SIGN_MANB_RESPONSE,
                actual: reply.response_code,
            });
        }
        if reply.body.len() != BRIDGE_SIGN_MANB_RESPONSE_BYTES {
            return Err(ManifestSignerError::UnexpectedResponseLength {
                expected: BRIDGE_SIGN_MANB_RESPONSE_BYTES,
                actual: reply.body.len(),
            });
        }

        let decoded = FdrManifestSignature::decode(&reply.body)
            .map_err(|error| ManifestSignerError::Broker(error.to_string()))?;
        let expected_body_length =
            u32::try_from(signed_body.len()).map_err(|_| ManifestSignerError::BodyTooLarge {
                length: signed_body.len(),
                maximum: MAX_SIGNED_BODY_BYTES,
            })?;
        if decoded.signed_body_length != expected_body_length {
            return Err(ManifestSignerError::UnexpectedSignedBodyLength {
                expected: expected_body_length,
                actual: decoded.signed_body_length,
            });
        }

        let digest = sha384(signed_body);
        if decoded.digest_sha384 != digest {
            return Err(ManifestSignerError::UnexpectedDigest {
                expected: Box::new(digest),
                actual: Box::new(decoded.digest_sha384),
            });
        }

        if decoded.signer_public_key_uncompressed != self.expected_public_key {
            return Err(ManifestSignerError::UnexpectedPublicKey {
                expected: Box::new(self.expected_public_key),
                actual: Box::new(decoded.signer_public_key_uncompressed),
            });
        }

        if !verify_uncompressed(
            &decoded.signer_public_key_uncompressed,
            &signing_digest(&digest),
            &decoded.signature_rs,
        ) {
            return Err(ManifestSignerError::InvalidSignature);
        }
        Ok(decoded.signature_rs)
    }
}

const REFUSED_BODY_TRACE_BYTES: usize = 64;

#[must_use]
pub fn service_base_url() -> String {
    format!("http://{FDR_SERVICE_ADDRESS}:{FDR_SERVICE_PORT}")
}

#[must_use]
pub fn is_service_destination(host: &str, port: u16) -> bool {
    port == FDR_SERVICE_PORT && host == FDR_SERVICE_ADDRESS
}

#[derive(Debug)]
pub enum SealServerError {
    Io(io::Error),
    RequestTooLarge { field: &'static str },
    RequestLine { line: String },
    BodyLength { announced: Option<String> },
    Material(FdrObjectError),
    Request(Pkcs10Error),
    Pem(PemError),
    Sealing(SealingRequestError),
    Manifest(SealManifestError),
    Signer(ManifestSignerError),
    SealingTarget { target: String },
    DataTarget { target: String },
    DataStore(io::Error),
}

impl std::fmt::Display for SealServerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::RequestTooLarge { field } => {
                write!(
                    formatter,
                    "the request's {field} is larger than the host will read"
                )
            }
            Self::RequestLine { line } => write!(formatter, "unreadable request line {line:?}"),
            Self::BodyLength { announced } => match announced {
                Some(value) => write!(formatter, "unusable Content-Length {value:?}"),
                None => write!(formatter, "the request carried no Content-Length"),
            },
            Self::Material(error) => write!(formatter, "{error}"),
            Self::Request(error) => write!(formatter, "{error}"),
            Self::Pem(error) => write!(formatter, "{error}"),
            Self::Sealing(error) => write!(formatter, "{error}"),
            Self::Manifest(error) => write!(formatter, "{error}"),
            Self::Signer(error) => write!(formatter, "{error}"),
            Self::SealingTarget { target } => write!(
                formatter,
                "the sealing path {target:?} names no <class>:<instance>"
            ),
            Self::DataTarget { target } => write!(
                formatter,
                "the data store path {target:?} names no readable <class>:<instance>"
            ),
            Self::DataStore(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SealServerError {}

impl From<io::Error> for SealServerError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<FdrObjectError> for SealServerError {
    fn from(error: FdrObjectError) -> Self {
        Self::Material(error)
    }
}

impl From<SealManifestError> for SealServerError {
    fn from(error: SealManifestError) -> Self {
        Self::Manifest(error)
    }
}

impl From<ManifestSignerError> for SealServerError {
    fn from(error: ManifestSignerError) -> Self {
        Self::Signer(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    #[must_use]
    pub fn path(&self) -> &str {
        self.target
            .split_once('?')
            .map_or(self.target.as_str(), |(path, _)| path)
    }
}

struct Buffered<'a, S: Read> {
    inner: &'a mut S,
    held: Vec<u8>,
    at: usize,
}

impl<'a, S: Read> Buffered<'a, S> {
    fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            held: Vec::new(),
            at: 0,
        }
    }

    fn byte(&mut self) -> io::Result<u8> {
        if self.at == self.held.len() {
            let mut chunk = [0u8; 2048];
            let read = self.inner.read(&mut chunk)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the peer closed the connection mid request",
                ));
            }
            self.held.clear();
            self.held.extend_from_slice(&chunk[..read]);
            self.at = 0;
        }
        let byte = self.held[self.at];
        self.at += 1;
        Ok(byte)
    }

    fn exact(&mut self, length: usize) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(length);
        while out.len() < length {
            if self.at < self.held.len() {
                let take = (length - out.len()).min(self.held.len() - self.at);
                out.extend_from_slice(&self.held[self.at..self.at + take]);
                self.at += take;
                continue;
            }
            out.push(self.byte()?);
        }
        Ok(out)
    }

    fn line(&mut self, field: &'static str) -> Result<String, SealServerError> {
        let mut out = Vec::new();
        loop {
            let byte = self.byte()?;
            if byte == b'\n' {
                if out.last() == Some(&b'\r') {
                    out.pop();
                }
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            out.push(byte);
            if out.len() > MAX_LINE {
                return Err(SealServerError::RequestTooLarge { field });
            }
        }
    }
}

pub fn read_request<S: Read>(stream: &mut S) -> Result<HttpRequest, SealServerError> {
    let mut reader = Buffered::new(stream);
    let line = reader.line("request line")?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some(_version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(SealServerError::RequestLine { line });
    };
    let method = method.to_string();
    let target = target.to_string();

    let mut headers = Vec::new();
    loop {
        let header = reader.line("header")?;
        if header.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Err(SealServerError::RequestTooLarge { field: "headers" });
        }
        if let Some((name, value)) = header.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    let announced = headers
        .iter()
        .find(|(key, _)| key == "content-length")
        .map(|(_, value)| value.clone());
    let length = match &announced {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| SealServerError::BodyLength {
                announced: announced.clone(),
            })?,
        None => return Err(SealServerError::BodyLength { announced: None }),
    };
    if length > MAX_REQUEST_BODY {
        return Err(SealServerError::BodyLength { announced });
    }
    let body = reader.exact(length)?;

    Ok(HttpRequest {
        method,
        target,
        headers,
        body,
    })
}

#[must_use]
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%' {
            let digits = bytes.get(at + 1..at + 3)?;
            let digits = std::str::from_utf8(digits).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8(out).ok()
}

fn data_resource(target: &str) -> Option<DataResource> {
    let (class, instance) = target.split_once(':')?;
    DataResource::new(&percent_decode(class)?, &percent_decode(instance)?)
}

fn write_response<S: Write>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    extra: &[(String, String)],
    body: &[u8],
) -> io::Result<()> {
    write_response_framed(
        stream,
        status,
        reason,
        content_type,
        extra,
        body.len(),
        body,
    )
}

fn write_response_framed<S: Write>(
    stream: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    extra: &[(String, String)],
    announced: usize,
    body: &[u8],
) -> io::Result<()> {
    use std::fmt::Write as _;

    let mut head = format!("HTTP/1.1 {status} {reason}\r\n");
    let _ = write!(head, "Content-Type: {content_type}\r\n");
    let _ = write!(head, "Content-Length: {announced}\r\n");
    for (name, value) in extra {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    head.push_str("Connection: close\r\n\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealServerOutcome {
    Certificate {
        version: u64,
        subject_bytes: usize,
        certificate_bytes: usize,
    },
    Seal {
        instance: String,
        classes: Vec<String>,
        manifest_bytes: usize,
    },
    DataServed {
        class: String,
        instance: String,
        bytes: usize,
        head: bool,
    },
    DataAbsent {
        class: String,
        instance: String,
        head: bool,
    },
    SealingManifest {
        instance: String,
        bytes: usize,
        served: u64,
        head: bool,
    },
    DataStored {
        class: String,
        instance: String,
        bytes: usize,
    },
    DataDeleted {
        class: String,
        instance: String,
        held: bool,
    },
    DataMethod {
        class: String,
        instance: String,
        method: String,
    },
    NotFound {
        path: String,
    },
    Refused {
        path: String,
        reason: String,
    },
}

pub struct SealServer {
    port: u16,
    armed_at_secs: f64,
    reporter: SharedReporter,
    instance: String,
    root_subject: DistinguishedName,
    root_key: P256PrivateKey,
    signer: Arc<dyn FdrManifestSigner>,
    signing_public_key: [u8; P256_UNCOMPRESSED_BYTES],
    signing_key_source: &'static str,
    leaf_certificate: Vec<u8>,
    not_before: i64,
    not_after: i64,
    store: FdrDataStore,
    sealing_manifests: Mutex<BTreeMap<String, SealingManifestRecord>>,
    certificates: AtomicU64,
    seals: AtomicU64,
    data_reads: AtomicU64,
    data_writes: AtomicU64,
}

struct SealingManifestRecord {
    manifest: Vec<u8>,
    served: u64,
}

impl SealServer {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        material: &FdrTrustMaterial,
        directory: &std::path::Path,
        instance: &str,
        signer: Arc<dyn FdrManifestSigner>,
        not_before: i64,
        not_after: i64,
        port: u16,
        armed_at_secs: f64,
        reporter: &SharedReporter,
    ) -> Result<Self, SealServerError> {
        let signing_public_key = signer.public_key();
        let signing_key_source = signer.source();
        let identity = CertificateIdentity {
            subject: DistinguishedName::new()
                .common_name(DEFAULT_LEAF_COMMON_NAME)
                .organization(DEFAULT_ORGANIZATION),
            serial: load_or_generate_serial(&directory.join(SEALING_LEAF_SERIAL_FILE_NAME))?,
            not_before,
            not_after,
        };
        let leaf_certificate = issue_fdr_leaf(
            &identity,
            &signing_public_key,
            material.root_ca_subject(),
            material.root_ca_key().private(),
            None,
        )
        .map_err(|error| SealServerError::Material(FdrObjectError::Pki(error)))?;
        let store = FdrDataStore::open(&directory.join(DATA_STORE_DIRECTORY))
            .map_err(SealServerError::DataStore)?;
        Ok(Self {
            port,
            armed_at_secs,
            reporter: std::sync::Arc::clone(reporter),
            instance: instance.to_string(),
            root_subject: material.root_ca_subject().clone(),
            root_key: *material.root_ca_key().private(),
            signer,
            signing_public_key,
            signing_key_source,
            leaf_certificate,
            not_before,
            not_after,
            store,
            sealing_manifests: Mutex::new(BTreeMap::new()),
            certificates: AtomicU64::new(0),
            seals: AtomicU64::new(0),
            data_reads: AtomicU64::new(0),
            data_writes: AtomicU64::new(0),
        })
    }

    #[must_use]
    pub fn leaf_certificate(&self) -> &[u8] {
        &self.leaf_certificate
    }

    #[must_use]
    pub fn signing_public_key(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        self.signing_public_key
    }

    #[must_use]
    pub fn signing_key_source(&self) -> &'static str {
        self.signing_key_source
    }

    #[must_use]
    pub fn store(&self) -> &FdrDataStore {
        &self.store
    }

    pub fn serve<S: Read + Write>(
        &self,
        stream: &mut S,
    ) -> Result<SealServerOutcome, SealServerError> {
        let began = Instant::now();
        let request = read_request(stream)?;
        let path = request.path().to_string();

        if path == CA_AUTHORIZE_PATH {
            return self.serve_authorize(stream, &request, &path, began);
        }
        if let Some(target) = path.strip_prefix(SEALING_SIGN_PREFIX) {
            let target = target.to_string();
            return self.serve_sealing(stream, &request, &path, &target, began);
        }
        if let Some(target) = path.strip_prefix(DATA_STORE_PREFIX) {
            let target = target.to_string();
            return self.serve_data(stream, &request, &path, &target, began);
        }

        let line = format!(
            "{FDR_SEAL_PREFIX} result=unserved-path port={} at={:.3}s elapsed={:.3}s method={} path={path:?} meaning=\"the guest reached the host's FDR service on a path the host does not serve, so it was answered 404 rather than left waiting; the host serves three paths, {CA_AUTHORIZE_PATH}, {SEALING_SIGN_PREFIX}<class>:<instance> and {DATA_STORE_PREFIX}<class>:<instance>\" detail=\"a path the host did not expect is a fact about what the guest asked for, and it belongs on the record rather than being answered with something plausible\"",
            self.port,
            self.armed_at_secs,
            began.elapsed().as_secs_f64(),
            request.method
        );
        report(&self.reporter, "unserved-path", &line);
        write_response(stream, 404, "Not Found", "text/plain", &[], b"")?;
        Ok(SealServerOutcome::NotFound { path })
    }

    fn serve_authorize<S: Read + Write>(
        &self,
        stream: &mut S,
        request: &HttpRequest,
        path: &str,
        began: Instant,
    ) -> Result<SealServerOutcome, SealServerError> {
        let issued = match self.issue_device_certificate(&request.body) {
            Ok(issued) => issued,
            Err(error) => {
                return self.refuse(stream, path, &request.body, &error.to_string(), began);
            }
        };
        let armoured = pem::encode(LABEL_CERTIFICATE, &issued.certificate);
        let count = self.certificates.fetch_add(1, Ordering::Relaxed) + 1;
        let line = format!(
            "{FDR_SEAL_PREFIX} result=certificate-issued port={} at={:.3}s elapsed={:.3}s request_bytes={} request_version={} subject_bytes={} certificate_bytes={} pem_bytes={} algorithm={} issued={count} meaning=\"the host answered the guest's certification request with a device certificate over the exact public key the request carried, issued by the root the trust object's trst element publishes; the request's own signature was verified first, so the key the host certified is one the guest proved it holds\" detail=\"request_version is what libFDR wrote and what the host read, not what the host required; a host that demanded RFC 2986's 0 would refuse the 2 libFDR sends and fail the whole restore. The body is a single PEM CERTIFICATE block because _AMFDRPermissionsRequest installs the response verbatim as amfdr->cert at 0x316d8 and persists it at 0x3182c, and _AMFDRDataHTTPLoadPersistent then runs _AMSupportX509CreateDerCertFromPEM over exactly those bytes at 0x30f18 and drops the certificate at 0x30f60 when it fails; a DER body would install once and then vanish on the reload. Only 200 and 202 are accepted, from (status & ~2) == 0xc8 at 0x33054\"",
            self.port,
            self.armed_at_secs,
            began.elapsed().as_secs_f64(),
            request.body.len(),
            issued.version,
            issued.subject_bytes,
            issued.certificate.len(),
            armoured.len(),
            issued.algorithm
        );
        report(&self.reporter, "certificate-issued", &line);

        write_response(
            stream,
            200,
            "OK",
            CONTENT_TYPE_PEM,
            &[],
            armoured.as_bytes(),
        )?;
        Ok(SealServerOutcome::Certificate {
            version: issued.version,
            subject_bytes: issued.subject_bytes,
            certificate_bytes: issued.certificate.len(),
        })
    }

    fn serve_sealing<S: Read + Write>(
        &self,
        stream: &mut S,
        request: &HttpRequest,
        path: &str,
        target: &str,
        began: Instant,
    ) -> Result<SealServerOutcome, SealServerError> {
        let Some((class, instance)) = target.split_once(':') else {
            let error = SealServerError::SealingTarget {
                target: target.to_string(),
            };
            return self.refuse(stream, path, &request.body, &error.to_string(), began);
        };
        let instance = if instance.is_empty() {
            self.instance.clone()
        } else {
            instance.to_string()
        };

        let manifest = match self.sign_seal(&request.body, &instance) {
            Ok(signed) => signed,
            Err(error) => {
                return self.refuse(stream, path, &request.body, &error.to_string(), began);
            }
        };

        let version = request
            .header(SEAL_VERSION_HEADER)
            .map_or_else(|| SEAL_DATA_VERSION.to_string(), str::to_string);
        let extra = vec![(SEAL_VERSION_HEADER.to_string(), version.clone())];

        let count = self.seals.fetch_add(1, Ordering::Relaxed) + 1;
        let line = format!(
            "{FDR_SEAL_PREFIX} result=seal-signed port={} at={:.3}s elapsed={:.3}s request_bytes={} class={class} instance={instance} classes=[{}] digests=[{}] manifest_bytes={} chain_certificates=1 seal_version={version} signed={count} meaning=\"the host signed the sealing manifest the guest asked for, and every digest in it came out of an IM4M the guest itself built and put on the wire; the host computed no digest and holds none of the class payloads, which is what makes this the guest driven route rather than the host preauthoring factory data\" detail=\"the response body is the bare IM4M DER and nothing else. The signature covers the complete SET element, tag and length header included, under SHA-384 with the leftmost 32 bytes signed by a P-256 key, which is the FIPS 186-4 leftmost min(N,outlen) rule. The certificate SET carries the leaf only: the self signed root is not in it because the guest already holds it out of the trust object's trst element and anchors the chain there. {SEAL_MANIFEST_VERSION_HEADER} is deliberately absent, because it is only sent when ManifestVersion2 is in the board's seal attributes and this board's are [Version2] alone\"",
            self.port,
            self.armed_at_secs,
            began.elapsed().as_secs_f64(),
            request.body.len(),
            manifest.classes.join(","),
            manifest.digests.join(","),
            manifest.manifest.len()
        );
        report(&self.reporter, "seal-signed", &line);

        write_response(
            stream,
            200,
            "OK",
            CONTENT_TYPE_OCTET_STREAM,
            &extra,
            &manifest.manifest,
        )?;
        Ok(SealServerOutcome::Seal {
            instance,
            classes: manifest.classes,
            manifest_bytes: manifest.manifest.len(),
        })
    }

    fn serve_data<S: Read + Write>(
        &self,
        stream: &mut S,
        request: &HttpRequest,
        path: &str,
        target: &str,
        began: Instant,
    ) -> Result<SealServerOutcome, SealServerError> {
        let Some(resource) = data_resource(target) else {
            let error = SealServerError::DataTarget {
                target: target.to_string(),
            };
            return self.refuse(stream, path, &request.body, &error.to_string(), began);
        };
        let key = resource.key();
        let method = request.method.to_ascii_uppercase();
        let sik = resource.sik_instance();
        let described = sik.as_ref().map_or_else(
            || String::from("plain"),
            |sik| {
                format!(
                    "sik instance={} key_bytes={} uncompressed={}",
                    sik.instance,
                    sik.public_key.len(),
                    sik.looks_uncompressed()
                )
            },
        );

        match method.as_str() {
            "GET" | "HEAD" => {
                let head = method == "HEAD";
                let held = self.store.get(&key);
                let count = self.data_reads.fetch_add(1, Ordering::Relaxed) + 1;
                match held {
                    Some(record) => {
                        let line = format!(
                            "{FDR_SEAL_PREFIX} result=data-served port={} at={:.3}s elapsed={:.3}s method={method} class={} instance={} form=\"{described}\" key={key} record_bytes={} head={head} reads={count} store_entries={} meaning=\"the host's FDR data store holds a record under this resource and served it; every byte of it came out of a put the guest itself made, so this is the device reading back what it sealed rather than the host producing factory data\" detail=\"the response is the bare record and nothing else. _AMFDRDataHTTPCopy installs the body verbatim at 0x35e78 and only 200 and 202 are accepted at 0x33054, so nothing is wrapped around it. A HEAD carries the length and no body because _AMFDRDataHTTPPresent only reads whether the request succeeded\"",
                            self.port,
                            self.armed_at_secs,
                            began.elapsed().as_secs_f64(),
                            resource.class,
                            resource.instance,
                            record.len(),
                            self.store.len()
                        );
                        report(&self.reporter, "data-served", &line);
                        let body: &[u8] = if head { &[] } else { &record };
                        write_response_framed(
                            stream,
                            200,
                            "OK",
                            CONTENT_TYPE_OCTET_STREAM,
                            &[],
                            record.len(),
                            body,
                        )?;
                        Ok(SealServerOutcome::DataServed {
                            class: resource.class,
                            instance: resource.instance,
                            bytes: record.len(),
                            head,
                        })
                    }
                    None if resource.class == SEAL_CLASS => self.serve_sealing_manifest(
                        stream, &resource, &key, &described, head, count, began,
                    ),
                    None => {
                        let line = format!(
                            "{FDR_SEAL_PREFIX} result=data-absent port={} at={:.3}s elapsed={:.3}s method={method} class={} instance={} form=\"{described}\" key={key} head={head} reads={count} store_entries={} store_keys=[{}] meaning=\"the host's FDR data store holds no record under this resource, so it answered {STATUS_NOT_FOUND} and said so; a machine restoring to blank storage that has never sealed anything legitimately has no prior record, and nothing was invented to fill the gap\" detail=\"{STATUS_NOT_FOUND} is the store's own way of saying absent, not an error the host chose: _AMFDRDataHTTPPresent runs _AMFDRGetUnderlyingErrorCode at 0x35cb4, compares 0x194 at 0x35cb8, logs 'clearing expected kAMFDRServerErrorNotFound error' and drops the error. A 204 would be a hard failure because __AMFDRHttpRequestSendSyncNoRetry accepts only 200 and 202 at 0x33054, and a 200 with an empty body would put _AMFDRDataHTTPCopy on 'outValueData is NULL' at 0x35f68, which the guest cannot read as absence. Expect _AMFDRSealingMapRecoverCurrentDevice at 0x6889c to log 'could not populate the local sealing manifest, skipping' and carry on\"",
                            self.port,
                            self.armed_at_secs,
                            began.elapsed().as_secs_f64(),
                            resource.class,
                            resource.instance,
                            self.store.len(),
                            self.store.keys().join(",")
                        );
                        report(&self.reporter, "data-absent", &line);
                        write_response(
                            stream,
                            STATUS_NOT_FOUND,
                            "Not Found",
                            "text/plain",
                            &[],
                            b"",
                        )?;
                        Ok(SealServerOutcome::DataAbsent {
                            class: resource.class,
                            instance: resource.instance,
                            head,
                        })
                    }
                }
            }
            "PUT" => {
                if let Err(error) = self.store.put(&key, &request.body) {
                    let reason = SealServerError::DataStore(error).to_string();
                    return self.refuse(stream, path, &request.body, &reason, began);
                }
                let count = self.data_writes.fetch_add(1, Ordering::Relaxed) + 1;
                let line = format!(
                    "{FDR_SEAL_PREFIX} result=data-stored port={} at={:.3}s elapsed={:.3}s class={} instance={} form=\"{described}\" key={key} record_bytes={} writes={count} store_entries={} meaning=\"the guest put a record into the host's FDR data store and the host holds it exactly as sent; this is the whole of how a record ever enters the store, which is what keeps the host out of the business of authoring factory data\" detail=\"the record persists under {DATA_STORE_DIRECTORY} beside the trust material, so the same machine reads it back on a later run: the store is the remote one the FDRDataStoreURL option names, and a remote store that forgot everything when the ramdisk went away would never answer a recover\"",
                    self.port,
                    self.armed_at_secs,
                    began.elapsed().as_secs_f64(),
                    resource.class,
                    resource.instance,
                    request.body.len(),
                    self.store.len()
                );
                report(&self.reporter, "data-stored", &line);
                write_response(stream, 200, "OK", CONTENT_TYPE_OCTET_STREAM, &[], b"")?;
                Ok(SealServerOutcome::DataStored {
                    class: resource.class,
                    instance: resource.instance,
                    bytes: request.body.len(),
                })
            }
            "DELETE" => {
                let held = match self.store.remove(&key) {
                    Ok(held) => held,
                    Err(error) => {
                        let reason = SealServerError::DataStore(error).to_string();
                        return self.refuse(stream, path, &request.body, &reason, began);
                    }
                };
                let line = format!(
                    "{FDR_SEAL_PREFIX} result=data-deleted port={} at={:.3}s elapsed={:.3}s class={} instance={} form=\"{described}\" key={key} held={held} store_entries={} meaning=\"the guest asked the host's FDR data store to drop this record and it was dropped; held says whether one was there, so a delete of something the host never had is on the record as exactly that\" detail=\"_AMFDRDataHTTPDelete at 0x36178 aims DELETE at the same resource GET reads, and it takes any 200 or 202 as done\"",
                    self.port,
                    self.armed_at_secs,
                    began.elapsed().as_secs_f64(),
                    resource.class,
                    resource.instance,
                    self.store.len()
                );
                report(&self.reporter, "data-deleted", &line);
                write_response(stream, 200, "OK", CONTENT_TYPE_OCTET_STREAM, &[], b"")?;
                Ok(SealServerOutcome::DataDeleted {
                    class: resource.class,
                    instance: resource.instance,
                    held,
                })
            }
            _ => {
                let line = format!(
                    "{FDR_SEAL_PREFIX} result=data-method-unserved port={} at={:.3}s elapsed={:.3}s method={method} class={} instance={} form=\"{described}\" key={key} body_bytes={} meaning=\"the guest named a data store resource with a method the host does not serve on it, so it was answered {STATUS_NOT_FOUND} and the method is on the record; the host serves GET, HEAD, PUT and DELETE, which are the four libFDR aims at dm/data\" detail=\"a verb the host did not expect is a fact about what the guest asked for, and it belongs here rather than being answered with something plausible\"",
                    self.port,
                    self.armed_at_secs,
                    began.elapsed().as_secs_f64(),
                    resource.class,
                    resource.instance,
                    request.body.len()
                );
                report(&self.reporter, "data-method-unserved", &line);
                write_response(
                    stream,
                    STATUS_NOT_FOUND,
                    "Not Found",
                    "text/plain",
                    &[],
                    b"",
                )?;
                Ok(SealServerOutcome::DataMethod {
                    class: resource.class,
                    instance: resource.instance,
                    method,
                })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn serve_sealing_manifest<S: Read + Write>(
        &self,
        stream: &mut S,
        resource: &DataResource,
        key: &str,
        described: &str,
        head: bool,
        reads: u64,
        began: Instant,
    ) -> Result<SealServerOutcome, SealServerError> {
        let plain = resource.plain_instance();
        if plain != self.instance {
            let line = format!(
                "{FDR_SEAL_PREFIX} result=sealing-manifest-not-this-machine port={} at={:.3}s elapsed={:.3}s class={} instance={} form=\"{described}\" key={key} plain_instance={plain} machine_instance={} head={head} reads={reads} meaning=\"the guest asked for a sealing manifest under a data instance identifier that is not the one this machine's chip id and ECID render, so the host answered {STATUS_NOT_FOUND} instead of authoring one; the host signs a manifest about the device it presents and about no other\" detail=\"the machine identifier comes from machine_instance_identifier over the firmware record's chip id and the configured ECID, rendered %08X-%016llX by the device identifier formatter, so it follows the machine rather than any board table. plain_instance is the requested instance with any sik- wrapping stripped the way _AMFDRDataInstanceCopyNonSik strips it at 0x10248\"",
                self.port,
                self.armed_at_secs,
                began.elapsed().as_secs_f64(),
                resource.class,
                resource.instance,
                self.instance
            );
            report(&self.reporter, "sealing-manifest-not-this-machine", &line);
            write_response(
                stream,
                STATUS_NOT_FOUND,
                "Not Found",
                "text/plain",
                &[],
                b"",
            )?;
            return Ok(SealServerOutcome::DataAbsent {
                class: resource.class.clone(),
                instance: resource.instance.clone(),
                head,
            });
        }

        let (manifest, served) = match self.sealing_manifest_for(key, &plain) {
            Ok(authored) => authored,
            Err(error) => {
                let line = format!(
                    "{FDR_SEAL_PREFIX} result=sealing-manifest-unauthored port={} at={:.3}s elapsed={:.3}s class={} instance={} form=\"{described}\" key={key} head={head} reads={reads} meaning=\"the host could not author the sealing manifest for this machine, so the resource kept the {STATUS_NOT_FOUND} it had before rather than being answered with something that would not decode; the reason is in detail and the guest then fails on sealingManifest is NULL\" detail=\"{error}\"",
                    self.port,
                    self.armed_at_secs,
                    began.elapsed().as_secs_f64(),
                    resource.class,
                    resource.instance
                );
                report(&self.reporter, "sealing-manifest-unauthored", &line);
                write_response(
                    stream,
                    STATUS_NOT_FOUND,
                    "Not Found",
                    "text/plain",
                    &[],
                    b"",
                )?;
                return Ok(SealServerOutcome::DataAbsent {
                    class: resource.class.clone(),
                    instance: resource.instance.clone(),
                    head,
                });
            }
        };

        let result = if served == 1 {
            "sealing-manifest-served"
        } else {
            "sealing-manifest-repeated"
        };
        let signing_public = self.signing_public_key();
        let (sik_key, sik_match) = match resource.sik_instance() {
            Some(sik) => {
                let matched = sik.public_key.as_slice() == signing_public.as_slice();
                (
                    hex_digest(&sik.public_key),
                    if matched { "yes" } else { "no" },
                )
            }
            None => (String::from("none"), "absent"),
        };
        let line = format!(
            "{FDR_SEAL_PREFIX} result={result} port={} at={:.3}s elapsed={:.3}s class={} instance={} form=\"{described}\" key={key} plain_instance={plain} manifest_bytes={} served={served} head={head} reads={reads} store_entries={} signing_key_source={} signing_key={} sik_key={sik_key} sik_match={sik_match} meaning=\"the host authored a sealing manifest for the device it presents and served it with 200; this is a PARSE ONLY manifest, its MANB carries MANP and nothing else, so it names the device and asserts no DGST for any data class, and it is NOT a stored factory record: the data store was not written and store_entries is what it was before, so every other class still reads absent out of it. sik_match=yes is the whole verification question answered on the wire: the key the guest spelled into the instance is the key the host signed with, so _AMFDRDecodeEcdsaVerifySignature at 0x67e28 is verifying under the host's own signer. sik_match=no means the two keys differ and the trust evaluation cannot pass whatever else is right\" detail=\"the body is the bare IM4M DER. It exists to satisfy _AMFDRDataDecodeAndSetSealingManifest at 0x10380, which runs _AMFDRDecodeManifestBody at 0x1dedc and on a 0 return takes the direct path at 0x104f0 and sets SealingManifest to the body whole; 0x1dedc wants Img4DecodeInitManifest to succeed, a SET at +0x118, a version INTEGER at +0x108, the MANB tag {MANIFEST_BODY_DER_TAG:#x} found, and DERDecodeSeqContentInit to open the MANB body. No meta property is emitted because 0x10380 treats it as optional at cbz w0,0x106c0 and a meta would oblige the host to supply every minimal-manifest record it names. Nothing on the populate path at 0x26274 verifies a signature, but _AMFDRSealedDataVerify at 0x4c070 and __AMFDRSealingManifestTrustEvaluation at 0x27964 both reach _AMFDRDataVerifySealingManifestInternal at 0xeb4c, and at signing version 2 that verifier takes its key from _AMFDRCryptoGetSikPub at 0xec14 rather than from any Apple root: the legacy Img4 core __Img4DecodePerformTrustEvaluationWithCallbacksInternal at 0x25564 in libimg4 checks no signature and references no root at all, and the embedded ApplePlatformRootCAG1 material at 0x495c0 belongs to the separate image4_trust_evaluate API the AP boot manifest uses. So the key on this line, not the certificate chain, is what that path turns on\"",
            self.port,
            self.armed_at_secs,
            began.elapsed().as_secs_f64(),
            resource.class,
            resource.instance,
            manifest.len(),
            self.store.len(),
            self.signing_key_source,
            hex_digest(&signing_public)
        );
        report(&self.reporter, result, &line);

        let body: &[u8] = if head { &[] } else { &manifest };
        write_response_framed(
            stream,
            200,
            "OK",
            CONTENT_TYPE_OCTET_STREAM,
            &[],
            manifest.len(),
            body,
        )?;
        Ok(SealServerOutcome::SealingManifest {
            instance: resource.instance.clone(),
            bytes: manifest.len(),
            served,
            head,
        })
    }

    // Authored once and kept: each manifest carries its own `srvn` nonce, so re-authoring would answer two reads of one resource with different bytes.
    fn sealing_manifest_for(
        &self,
        key: &str,
        instance: &str,
    ) -> Result<(Vec<u8>, u64), SealServerError> {
        let mut authored = self
            .sealing_manifests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = authored.get_mut(key) {
            record.served += 1;
            return Ok((record.manifest.clone(), record.served));
        }

        let mut properties = ManifestProperties::new(random_server_nonce()?, MANIFEST_FAIC);
        properties.instance = Some(instance.to_string());
        let signed_body = encode_properties_only_body(&properties)?;
        let signature = self
            .signer
            .sign_manb_body(&signed_body)
            .map_err(|error| SealManifestError::Entropy(io::Error::other(error.to_string())))?;
        let signed = build_manifest_from_signed_body(
            signed_body,
            &[self.leaf_certificate.as_slice()],
            signature,
        )?;
        let manifest = signed.manifest().to_vec();
        authored.insert(
            key.to_string(),
            SealingManifestRecord {
                manifest: manifest.clone(),
                served: 1,
            },
        );
        Ok((manifest, 1))
    }

    fn refuse<S: Write>(
        &self,
        stream: &mut S,
        path: &str,
        body: &[u8],
        reason: &str,
        began: Instant,
    ) -> Result<SealServerOutcome, SealServerError> {
        let head = body
            .iter()
            .take(REFUSED_BODY_TRACE_BYTES)
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let line = format!(
            "{FDR_SEAL_PREFIX} result=request-refused port={} at={:.3}s elapsed={:.3}s path={path:?} body_bytes={} body_head={head} meaning=\"the guest's request reached the host and the host could not answer it; nothing was invented to fill the gap, so the guest gets a 400 and fails on the reason named here rather than on a response that looks right\" detail=\"{reason}\"",
            self.port,
            self.armed_at_secs,
            began.elapsed().as_secs_f64(),
            body.len()
        );
        report(&self.reporter, "request-refused", &line);
        write_response(stream, 400, "Bad Request", "text/plain", &[], b"")?;
        Ok(SealServerOutcome::Refused {
            path: path.to_string(),
            reason: reason.to_string(),
        })
    }

    pub fn issue_device_certificate(
        &self,
        body: &[u8],
    ) -> Result<IssuedCertificate, SealServerError> {
        let der = if pem::looks_like_pem(body) {
            pem::decode(body, LABEL_CERTIFICATE_REQUEST).map_err(SealServerError::Pem)?
        } else {
            body.to_vec()
        };

        let request = pkcs10::parse_and_verify(&der).map_err(SealServerError::Request)?;
        let serial = random_serial()
            .map_err(|error| SealServerError::Material(FdrObjectError::Pki(error)))?;
        let certificate = issue_fdr_device_certificate(
            request.subject,
            &request.subject_public_key,
            &self.root_subject,
            &self.root_key,
            serial,
            self.not_before,
            self.not_after,
        )
        .map_err(|error| SealServerError::Material(FdrObjectError::Pki(error)))?;

        Ok(IssuedCertificate {
            version: request.version,
            subject_bytes: request.subject.len(),
            algorithm: request.digest.name(),
            certificate,
        })
    }

    pub fn sign_seal(&self, body: &[u8], instance: &str) -> Result<SignedSeal, SealServerError> {
        let request = parse_sealing_request(body).map_err(SealServerError::Sealing)?;
        let digests = request.class_digests().map_err(SealServerError::Sealing)?;

        let mut objects = Vec::with_capacity(digests.len());
        let mut classes = Vec::with_capacity(digests.len());
        let mut rendered = Vec::with_capacity(digests.len());
        for entry in &digests {
            let mut object = SealObject::new(&entry.class, &entry.digest);
            if let Some(named) = &entry.instance
                && named != instance
            {
                object.instance = Some(named.clone());
            }
            classes.push(entry.class.clone());
            rendered.push(format!(
                "{}={}",
                entry.class,
                entry
                    .digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            ));
            objects.push(object);
        }

        let properties = ManifestProperties::new(random_server_nonce()?, MANIFEST_FAIC);
        let signed_body = encode_signed_body(instance, &properties, &objects)?;
        let signature = self.signer.sign_manb_body(&signed_body)?;
        let signed = build_manifest_from_signed_body(
            signed_body,
            &[self.leaf_certificate.as_slice()],
            signature,
        )?;

        Ok(SignedSeal {
            manifest: signed.manifest().to_vec(),
            classes,
            digests: rendered,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedCertificate {
    pub version: u64,
    pub subject_bytes: usize,
    pub algorithm: &'static str,
    pub certificate: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedSeal {
    pub manifest: Vec<u8>,
    pub classes: Vec<String>,
    pub digests: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::P256PrivateKey;
    use std::sync::Arc;

    #[test]
    fn the_query_string_is_not_part_of_the_path() {
        let request = HttpRequest {
            method: "POST".to_string(),
            target: "/ca/authorize?attempt=2".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert_eq!(request.path(), CA_AUTHORIZE_PATH);
    }

    #[test]
    fn headers_are_matched_without_regard_to_case() {
        let mut body = b"POST /ca/authorize HTTP/1.1\r\n".to_vec();
        body.extend_from_slice(b"Content-Length: 4\r\nX-FDR-Seal-Version: 2\r\n\r\nabcd");
        let request = read_request(&mut body.as_slice()).expect("request");
        assert_eq!(request.header(SEAL_VERSION_HEADER), Some("2"));
        assert_eq!(request.body, b"abcd");
        assert_eq!(request.method, "POST");
    }

    #[test]
    fn a_request_with_no_content_length_is_refused() {
        let body = b"POST /ca/authorize HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
        assert!(matches!(
            read_request(&mut body.as_slice()),
            Err(SealServerError::BodyLength { announced: None })
        ));
    }

    #[test]
    fn only_the_local_service_is_accepted() {
        assert!(is_service_destination(
            FDR_SERVICE_ADDRESS,
            FDR_SERVICE_PORT
        ));
        assert!(!is_service_destination("gg.apple.com", 443));
        assert!(!is_service_destination(FDR_SERVICE_ADDRESS, 443));
        assert!(!is_service_destination("192.0.2.2", FDR_SERVICE_PORT));
    }

    #[test]
    fn the_published_url_names_the_service() {
        assert_eq!(service_base_url(), "http://192.0.2.1:8062");
    }

    const SIK_TARGET: &str = "seal:sik%2D00008103%2D1122334455667788%2D040102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40";

    fn sik_path() -> String {
        format!("{DATA_STORE_PREFIX}{SIK_TARGET}")
    }

    #[test]
    fn a_sik_data_path_decodes_into_its_class_and_instance() {
        let target = sik_path()
            .strip_prefix(DATA_STORE_PREFIX)
            .expect("prefix")
            .to_string();
        let resource = data_resource(&target).expect("resource");
        assert_eq!(resource.class, "seal");
        assert_eq!(
            resource.instance,
            "sik-00008103-1122334455667788-040102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40"
        );
        assert_eq!(resource.plain_instance(), "00008103-1122334455667788");
        let sik = resource.sik_instance().expect("sik form");
        assert_eq!(sik.public_key.len(), 65);
        assert_eq!(sik.public_key[0], 0x04);
    }

    #[test]
    fn each_side_of_the_resource_is_decoded_on_its_own() {
        assert_eq!(percent_decode("a%2Db").as_deref(), Some("a-b"));
        assert_eq!(percent_decode("%3A").as_deref(), Some(":"));
        assert_eq!(percent_decode("plain").as_deref(), Some("plain"));
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%"), None);
        let resource = data_resource("a%3Ab:inst").expect("resource");
        assert_eq!(resource.class, "a:b");
        assert_eq!(resource.instance, "inst");
    }

    #[test]
    fn a_data_path_with_no_resource_names_nothing() {
        assert_eq!(data_resource("seal"), None);
        assert_eq!(data_resource("seal:"), None);
        assert_eq!(data_resource(":inst"), None);
    }

    #[test]
    fn an_unheld_record_is_answered_with_the_status_libfdr_clears() {
        let store = FdrDataStore::in_memory();
        let resource = data_resource(SIK_TARGET).expect("resource");
        assert_eq!(store.get(&resource.key()), None);
        assert_eq!(STATUS_NOT_FOUND, 0x194);
    }

    #[test]
    fn the_sealing_manifest_branch_is_the_seal_class_alone() {
        let resource = data_resource(SIK_TARGET).expect("resource");
        assert_eq!(resource.class, SEAL_CLASS);
        for other in ["appv", "pcrt", "lcrt", "FSCl", "hop0", "HmCA"] {
            let target = format!("{other}:00008103-1122334455667788");
            let resource = data_resource(&target).expect("resource");
            assert_ne!(resource.class, SEAL_CLASS);
        }
    }

    #[test]
    fn a_record_the_guest_put_comes_back_under_the_same_resource() {
        let store = FdrDataStore::in_memory();
        let resource = data_resource(SIK_TARGET).expect("resource");
        let key = resource.key();
        store.put(&key, b"IM4M").expect("put");
        assert_eq!(store.get(&key), Some(b"IM4M".to_vec()));
        let plain = data_resource("seal:00008103-1122334455667788").expect("resource");
        assert_eq!(store.get(&plain.key()), None);
        assert!(store.remove(&key).expect("remove"));
        assert_eq!(store.get(&key), None);
    }

    #[test]
    fn a_bodyless_data_request_reads_as_a_request() {
        let mut wire = format!("GET {} HTTP/1.1\r\n", sik_path()).into_bytes();
        wire.extend_from_slice(b"Content-Length: 0\r\nx-fdr-client-id: appleutils\r\n\r\n");
        let request = read_request(&mut wire.as_slice()).expect("request");
        assert_eq!(request.method, "GET");
        assert_eq!(request.body, Vec::<u8>::new());
        assert_eq!(request.path(), sik_path());
        let target = request
            .path()
            .strip_prefix(DATA_STORE_PREFIX)
            .expect("prefix")
            .to_string();
        assert!(data_resource(&target).is_some());
    }

    #[test]
    fn a_head_answer_announces_the_length_without_the_body() {
        let mut wire = Vec::new();
        write_response_framed(&mut wire, 200, "OK", CONTENT_TYPE_OCTET_STREAM, &[], 9, b"")
            .expect("write");
        let text = String::from_utf8(wire).expect("utf8");
        assert!(text.contains("Content-Length: 9"), "{text}");
        assert!(text.ends_with("\r\n\r\n"), "{text}");
    }

    #[derive(Clone)]
    struct FixedBroker {
        reply: SessionReply,
    }

    impl SessionBroker for FixedBroker {
        fn request(&self, request_code: u16, body: &[u8]) -> Result<SessionReply, String> {
            assert_eq!(request_code, BRIDGE_SIGN_MANB_REQUEST);
            SignFdrManifestRequest::decode(body)
                .map_err(|error| format!("invalid signing request: {error}"))?;
            Ok(self.reply.clone())
        }
    }

    fn test_key() -> P256PrivateKey {
        P256PrivateKey::derive(&[0x41; 32], b"seal server remote signer test")
    }

    fn canonical_manb_body() -> Vec<u8> {
        let mut properties = ManifestProperties::new([0x31; 32], true);
        properties.instance = Some("00008103-1122334455667788".to_string());
        encode_properties_only_body(&properties).expect("canonical MANB body")
    }

    fn valid_reply(body: &[u8]) -> SessionReply {
        let key = test_key();
        let digest = sha384(body);
        let signature = key.sign_digest(&signing_digest(&digest));
        SessionReply {
            response_code: BRIDGE_SIGN_MANB_RESPONSE,
            body: FdrManifestSignature {
                signed_body_length: u32::try_from(body.len()).expect("body length"),
                digest_sha384: digest,
                signature_rs: signature,
                signer_public_key_uncompressed: key.public_uncompressed(),
            }
            .encode(),
        }
    }

    #[test]
    fn the_remote_manifest_signer_accepts_a_matching_reply() {
        let key = test_key();
        let body = canonical_manb_body();
        let signer = RemoteManifestSigner::new(
            Arc::new(FixedBroker {
                reply: valid_reply(&body),
            }),
            key.public_uncompressed(),
        );
        let signature = signer.sign_manb_body(&body).expect("signature");
        assert!(verify_uncompressed(
            &key.public_uncompressed(),
            &signing_digest(&sha384(&body)),
            &signature
        ));
    }

    #[test]
    fn the_remote_manifest_signer_rejects_a_digest_mismatch() {
        let key = test_key();
        let body = canonical_manb_body();
        let mut reply = valid_reply(&body);
        reply.body[8] ^= 0x01;
        let signer =
            RemoteManifestSigner::new(Arc::new(FixedBroker { reply }), key.public_uncompressed());
        assert!(matches!(
            signer.sign_manb_body(&body),
            Err(ManifestSignerError::UnexpectedDigest { .. })
        ));
    }

    #[test]
    fn the_remote_manifest_signer_rejects_a_public_key_mismatch() {
        let key = test_key();
        let body = canonical_manb_body();
        let other = P256PrivateKey::derive(&[0x52; 32], b"seal server remote signer test");
        let signer = RemoteManifestSigner::new(
            Arc::new(FixedBroker {
                reply: valid_reply(&body),
            }),
            other.public_uncompressed(),
        );
        let error = signer
            .sign_manb_body(&body)
            .expect_err("public key mismatch");
        assert!(matches!(
            error,
            ManifestSignerError::UnexpectedPublicKey { .. }
        ));
        assert_ne!(key.public_uncompressed(), other.public_uncompressed());
    }

    #[test]
    fn the_remote_manifest_signer_rejects_an_invalid_signature() {
        let key = test_key();
        let body = canonical_manb_body();
        let mut reply = valid_reply(&body);
        reply.body[119] ^= 0x01;
        let signer =
            RemoteManifestSigner::new(Arc::new(FixedBroker { reply }), key.public_uncompressed());
        assert!(matches!(
            signer.sign_manb_body(&body),
            Err(ManifestSignerError::InvalidSignature)
        ));
    }
}
