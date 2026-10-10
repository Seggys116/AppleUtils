use std::collections::BTreeSet;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use plist::{Dictionary, Value};

use super::bulk::{
    DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT, DEFAULT_DATA_PORT_RETRY_INTERVAL, DEFAULT_DATA_PORT_WINDOW,
};
use super::codec::{PlistFormat, write_message};
use super::dial::{DialCancellation, DialPlan, GuestDialer, SystemClock, dial_until};
use super::message::{DataRequest, DataType};
use super::provider::{
    BulkOutcome, BulkTransferService, BulkTransferTask, ProviderError, RestoreDataProvider,
    StreamedObject,
};

pub fn is_http_asset(data_type: &DataType) -> bool {
    matches!(
        data_type.wire_name(),
        "URLAsset" | "StreamedImageDecryptionKey"
    )
}

struct AssetRequest<'a> {
    method: &'static str,
    url: &'a str,
    headers: Vec<(&'a str, &'a str)>,
    body: Option<&'a [u8]>,
}

fn validate_asset_url(url: &str) -> Result<(), ProviderError> {
    let parsed = reqwest::Url::parse(url).map_err(|error| {
        ProviderError::Other(format!("restore asset URL could not be parsed: {error}"))
    })?;
    let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
    let service_domain = ["apple.com", "cdn-apple.com"].iter().any(|domain| {
        host == *domain
            || host
                .strip_suffix(*domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    });
    let permitted = parsed.scheme() == "https"
        && parsed.port_or_known_default() == Some(443)
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && service_domain;
    #[cfg(test)]
    let permitted = permitted
        || (parsed.scheme() == "http"
            && host == "127.0.0.1"
            && parsed.username().is_empty()
            && parsed.password().is_none());
    if permitted {
        Ok(())
    } else {
        Err(ProviderError::Other(format!(
            "restore asset URL is outside the verified HTTPS Apple service domain: scheme={} host={} port={:?}",
            parsed.scheme(),
            host,
            parsed.port_or_known_default()
        )))
    }
}

fn redirect_url(current: &str, location: &str) -> Result<String, ProviderError> {
    let mut next = reqwest::Url::parse(current)
        .and_then(|base| base.join(location))
        .map_err(|error| {
            ProviderError::Other(format!(
                "restore asset redirect could not be resolved: {error}"
            ))
        })?;
    next.set_fragment(None);
    validate_asset_url(next.as_str())?;
    Ok(next.to_string())
}

fn asset_request(request: &DataRequest) -> Result<AssetRequest<'_>, ProviderError> {
    let expected_method = match request.data_type.wire_name() {
        "URLAsset" => "GET",
        "StreamedImageDecryptionKey" => "POST",
        name => {
            return Err(ProviderError::Unsupported {
                data_type: name.to_string(),
            });
        }
    };
    let method = request.argument_string("RequestMethod").ok_or_else(|| {
        ProviderError::Other(format!(
            "{} request has no RequestMethod",
            request.data_type
        ))
    })?;
    if method != expected_method {
        return Err(ProviderError::Other(format!(
            "{} requires {expected_method}, received {method:?}",
            request.data_type
        )));
    }
    let url = request.argument_string("RequestURL").ok_or_else(|| {
        ProviderError::Other(format!("{} request has no RequestURL", request.data_type))
    })?;
    validate_asset_url(url)?;
    let mut headers = Vec::new();
    if let Some(value) = request.arguments.get("RequestAdditionalHeaders") {
        let dictionary = value.as_dictionary().ok_or_else(|| {
            ProviderError::Other("RequestAdditionalHeaders is not a dictionary".to_string())
        })?;
        for (name, value) in dictionary {
            let value = value.as_string().ok_or_else(|| {
                ProviderError::Other(format!("HTTP request header {name:?} is not a string"))
            })?;
            if name.is_empty()
                || !name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || byte == 0x60
                        || b"!#$%&'*+-.^_|~".contains(&byte)
                })
                || value.contains(['\r', '\n', '\0'])
            {
                return Err(ProviderError::Other(format!(
                    "HTTP request header {name:?} is not a valid header field"
                )));
            }
            headers.push((name.as_str(), value));
        }
    }
    let body = if expected_method == "POST" {
        Some(
            request
                .arguments
                .get("RequestBody")
                .and_then(Value::as_data)
                .ok_or_else(|| {
                    ProviderError::Other(format!(
                        "{} request has no data RequestBody",
                        request.data_type
                    ))
                })?,
        )
    } else {
        None
    };
    Ok(AssetRequest {
        method: expected_method,
        url,
        headers,
        body,
    })
}

fn cancelled(stop: &AtomicBool, transfer_cancel: &AtomicBool) -> Result<(), ProviderError> {
    if stop.load(Ordering::Acquire) {
        return Err(ProviderError::Io(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            DialCancellation::OperatorStopped,
        )));
    }
    if transfer_cancel.load(Ordering::Acquire) {
        return Err(ProviderError::Io(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            DialCancellation::TransferFailed,
        )));
    }
    Ok(())
}

pub fn fetch_asset_response_with_cancellation(
    request: &DataRequest,
    operator_stop: &Arc<AtomicBool>,
    transfer_cancel: &Arc<AtomicBool>,
) -> Result<Dictionary, ProviderError> {
    cancelled(operator_stop, transfer_cancel)?;
    let asset = asset_request(request)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        tokio::select! {
            biased;
            error = wait_for_cancellation(operator_stop, transfer_cancel) => Err(error),
            response = fetch_asset(&asset, &request.data_type) => response,
        }
    });
    runtime.shutdown_background();
    result
}

async fn wait_for_cancellation(stop: &AtomicBool, transfer_cancel: &AtomicBool) -> ProviderError {
    loop {
        if let Err(error) = cancelled(stop, transfer_cancel) {
            return error;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn redirect_headers<'a>(
    headers: &mut Vec<(&'a str, &'a str)>,
    current: &reqwest::Url,
    next: &reqwest::Url,
    discard_body: bool,
) {
    let changes_origin = current.origin() != next.origin();
    headers.retain(|(name, _)| {
        let name = name.to_ascii_lowercase();
        if changes_origin
            && matches!(
                name.as_str(),
                "authorization" | "proxy-authorization" | "cookie" | "cookie2" | "host"
            )
        {
            return false;
        }
        !(discard_body
            && matches!(
                name.as_str(),
                "content-length" | "transfer-encoding" | "content-type" | "content-encoding"
            ))
    });
}

async fn fetch_asset(
    asset: &AssetRequest<'_>,
    data_type: &DataType,
) -> Result<Dictionary, ProviderError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .build()
        .map_err(|error| {
            ProviderError::Other(format!(
                "{data_type} HTTPS client could not be initialized: {error}"
            ))
        })?;
    let mut url = reqwest::Url::parse(asset.url).map_err(|error| {
        ProviderError::Other(format!(
            "{data_type} asset URL could not be parsed: {error}"
        ))
    })?;
    url.set_fragment(None);
    let mut method = asset.method;
    let mut headers = asset.headers.clone();
    let mut visited = BTreeSet::new();
    loop {
        validate_asset_url(url.as_str())?;
        if !visited.insert((method, url.to_string())) {
            return Err(ProviderError::Other(format!(
                "{data_type} HTTP request encountered a redirect cycle"
            )));
        }
        let mut outbound = if method == "POST" {
            client.post(url.clone()).body(asset.body.unwrap().to_vec())
        } else {
            client.get(url.clone())
        };
        for (name, value) in &headers {
            outbound = outbound.header(*name, *value);
        }
        let response = outbound.send().await.map_err(|error| {
            ProviderError::Other(format!("{data_type} HTTP request failed: {error}"))
        })?;
        let status = response.status().as_u16();
        if matches!(status, 301..=303 | 307 | 308)
            && let Some(location) = response.headers().get(reqwest::header::LOCATION)
        {
            let location = location.to_str().map_err(|error| {
                ProviderError::Other(format!(
                    "{data_type} HTTP redirect Location cannot be decoded: {error}"
                ))
            })?;
            let next =
                reqwest::Url::parse(&redirect_url(url.as_str(), location)?).map_err(|error| {
                    ProviderError::Other(format!(
                        "{data_type} HTTP redirect URL is invalid: {error}"
                    ))
                })?;
            let discard_body = method == "POST" && matches!(status, 301..=303);
            redirect_headers(&mut headers, &url, &next, discard_body);
            if discard_body {
                method = "GET";
            }
            url = next;
            continue;
        }
        let mut headers = Dictionary::new();
        for (name, value) in response.headers() {
            let value = value.to_str().map_err(|error| {
                ProviderError::Other(format!(
                    "{data_type} HTTP header {} cannot be represented in a plist: {error}",
                    name.as_str()
                ))
            })?;
            headers.insert(name.as_str().to_string(), Value::String(value.to_string()));
        }
        let body = response.bytes().await.map_err(|error| {
            ProviderError::Other(format!(
                "{data_type} HTTP response body could not be read: {error}"
            ))
        })?;
        let mut reply = Dictionary::new();
        reply.insert("ResponseBody".to_string(), Value::Data(body.to_vec()));
        reply.insert("ResponseBodyDone".to_string(), Value::Boolean(true));
        reply.insert("ResponseHeaders".to_string(), Value::Dictionary(headers));
        reply.insert(
            "ResponseStatus".to_string(),
            Value::Integer(u64::from(status).into()),
        );
        return Ok(reply);
    }
}

pub struct HttpAssetAnswers<P: ?Sized> {
    fallback: Box<P>,
    operator_stop: Arc<AtomicBool>,
    transfer_cancel: Arc<AtomicBool>,
}

impl<P: RestoreDataProvider + ?Sized> HttpAssetAnswers<P> {
    pub fn new(
        fallback: Box<P>,
        operator_stop: Arc<AtomicBool>,
        transfer_cancel: Arc<AtomicBool>,
    ) -> Self {
        Self {
            fallback,
            operator_stop,
            transfer_cancel,
        }
    }
}

impl<P: RestoreDataProvider + ?Sized> RestoreDataProvider for HttpAssetAnswers<P> {
    fn supply(&mut self, request: &DataRequest) -> Result<Dictionary, ProviderError> {
        if is_http_asset(&request.data_type) {
            fetch_asset_response_with_cancellation(
                request,
                &self.operator_stop,
                &self.transfer_cancel,
            )
        } else {
            self.fallback.supply(request)
        }
    }

    fn supply_streamed(
        &mut self,
        request: &DataRequest,
    ) -> Option<Result<StreamedObject, ProviderError>> {
        self.fallback.supply_streamed(request)
    }
}

pub struct HttpAssetTransfer<D> {
    dialer: D,
    operator_stop: Arc<AtomicBool>,
    transfer_cancel: Arc<AtomicBool>,
    attempt_timeout: Duration,
    retry_interval: Duration,
    window: Duration,
}

impl<D> HttpAssetTransfer<D> {
    pub fn new(
        dialer: D,
        operator_stop: Arc<AtomicBool>,
        transfer_cancel: Arc<AtomicBool>,
    ) -> Self {
        Self {
            dialer,
            operator_stop,
            transfer_cancel,
            attempt_timeout: DEFAULT_DATA_PORT_ATTEMPT_TIMEOUT,
            retry_interval: DEFAULT_DATA_PORT_RETRY_INTERVAL,
            window: DEFAULT_DATA_PORT_WINDOW,
        }
    }

    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    pub fn with_retry(mut self, attempt_timeout: Duration, retry_interval: Duration) -> Self {
        self.attempt_timeout = attempt_timeout;
        self.retry_interval = retry_interval;
        self
    }
}

impl<D: GuestDialer + Clone + Send + 'static> BulkTransferService for HttpAssetTransfer<D> {
    fn prepare(
        &mut self,
        port: u16,
        request: &DataRequest,
    ) -> Result<BulkTransferTask, ProviderError> {
        asset_request(request)?;
        let mut dialer = self.dialer.clone();
        let request = request.clone();
        let stop = Arc::clone(&self.operator_stop);
        let cancel = Arc::clone(&self.transfer_cancel);
        let plan = DialPlan {
            port,
            attempt_timeout: self.attempt_timeout,
            retry_interval: self.retry_interval,
            window: self.window,
        };
        Ok(Box::new(move || {
            let response = fetch_asset_response_with_cancellation(&request, &stop, &cancel)?;
            cancelled(&stop, &cancel)?;
            let mut connection =
                dial_until(&mut dialer, plan, &mut SystemClock).map_err(|error| {
                    ProviderError::Other(format!(
                        "{} HTTP response could not connect to guest port {port}: {error}",
                        request.data_type
                    ))
                })?;
            let bytes = write_message(
                &mut connection.stream,
                &Value::Dictionary(response),
                PlistFormat::Binary,
            )
            .map_err(|error| {
                ProviderError::Other(format!(
                    "{} HTTP response could not be sent on guest port {port}: {error}",
                    request.data_type
                ))
            })?;
            Ok(BulkOutcome::Served {
                bytes: bytes as u64,
                blocks: 1,
                initiates: 0,
                metadata_requests: 0,
                oob_requests: 0,
                oob_bytes: 0,
            })
        }))
    }
}

pub struct HttpAssetRouter<H, F> {
    http: H,
    fallback: F,
}

impl<H, F> HttpAssetRouter<H, F> {
    pub fn new(http: H, fallback: F) -> Self {
        Self { http, fallback }
    }

    pub fn fallback(&self) -> &F {
        &self.fallback
    }
}

impl<H: BulkTransferService, F: BulkTransferService> BulkTransferService for HttpAssetRouter<H, F> {
    fn prepare(
        &mut self,
        port: u16,
        request: &DataRequest,
    ) -> Result<BulkTransferTask, ProviderError> {
        if is_http_asset(&request.data_type) {
            self.http.prepare(port, request)
        } else {
            self.fallback.prepare(port, request)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn request(data_type: &str, method: &str, url: String) -> DataRequest {
        let mut arguments = Dictionary::new();
        arguments.insert("RequestURL".to_string(), Value::String(url));
        arguments.insert(
            "RequestMethod".to_string(),
            Value::String(method.to_string()),
        );
        DataRequest {
            data_type: DataType::from_wire(data_type),
            data_port: Some(12347),
            arguments,
            asynchronous: true,
            async_context_uuid: Some("image-key".to_string()),
        }
    }

    fn serve_once(response: Vec<u8>) -> (String, std::thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}/asset", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut byte = [0u8; 1];
            while !received.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).unwrap();
                received.push(byte[0]);
            }
            let header = String::from_utf8(received.clone()).unwrap();
            let length = header
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("Content-Length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            let offset = received.len();
            received.resize(offset + length, 0);
            stream.read_exact(&mut received[offset..]).unwrap();
            stream.write_all(&response).unwrap();
            received
        });
        (url, handle)
    }

    #[test]
    fn url_asset_returns_real_http_status_headers_and_binary_body() {
        let (url, server) = serve_once(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\nX-Asset: fcs\r\nConnection: close\r\n\r\n\x00\xff\x01\x02".to_vec()
        );
        let response = fetch_asset_response_with_cancellation(
            &request("URLAsset", "GET", url),
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let received = server.join().unwrap();
        assert!(received.starts_with(b"GET /asset HTTP/1.1\r\n"));
        assert_eq!(response["ResponseStatus"].as_unsigned_integer(), Some(404));
        assert_eq!(
            response["ResponseBody"].as_data(),
            Some(&b"\x00\xff\x01\x02"[..])
        );
        assert_eq!(response["ResponseBodyDone"].as_boolean(), Some(true));
        assert_eq!(
            response["ResponseHeaders"].as_dictionary().unwrap()["x-asset"].as_string(),
            Some("fcs")
        );
    }

    #[test]
    fn streamed_key_preserves_post_body_and_additional_headers() {
        let (url, server) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\nkey".to_vec()
        );
        let mut request = request("StreamedImageDecryptionKey", "POST", url);
        let body = b"\x00\x80\xff\x01wkms".to_vec();
        request
            .arguments
            .insert("RequestBody".to_string(), Value::Data(body.clone()));
        let mut headers = Dictionary::new();
        headers.insert(
            "Content-Type".to_string(),
            Value::String("application/octet-stream".to_string()),
        );
        headers.insert(
            "X-WKMS-Session".to_string(),
            Value::String("restore-session".to_string()),
        );
        request.arguments.insert(
            "RequestAdditionalHeaders".to_string(),
            Value::Dictionary(headers),
        );
        let response = fetch_asset_response_with_cancellation(
            &request,
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let received = server.join().unwrap();
        let boundary = received
            .windows(4)
            .position(|word| word == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert!(received.starts_with(b"POST /asset HTTP/1.1\r\n"));
        assert_eq!(&received[boundary..], &body);
        let header = String::from_utf8(received[..boundary].to_vec()).unwrap();
        assert!(
            header
                .to_ascii_lowercase()
                .contains("x-wkms-session: restore-session\r\n")
        );
        assert_eq!(response["ResponseBody"].as_data(), Some(&b"key"[..]));
        assert_eq!(response["ResponseStatus"].as_unsigned_integer(), Some(200));
    }

    #[test]
    fn streamed_key_reply_reaches_requested_guest_port_as_binary_plist() {
        #[derive(Clone)]
        struct ReplyPort {
            address: std::net::SocketAddr,
            dialed: Arc<std::sync::Mutex<Vec<u16>>>,
        }
        impl GuestDialer for ReplyPort {
            type Stream = std::net::TcpStream;
            fn dial(&mut self, port: u16, timeout: Duration) -> io::Result<Self::Stream> {
                self.dialed.lock().unwrap().push(port);
                std::net::TcpStream::connect_timeout(&self.address, timeout)
            }
        }

        let key_body = b"\x00\xff\x80\x13";
        let (url, http) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n\x00\xff\x80\x13".to_vec()
        );
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let dialed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let dialer = ReplyPort {
            address: listener.local_addr().unwrap(),
            dialed: Arc::clone(&dialed),
        };
        let guest = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut prefix = [0u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut body).unwrap();
            (prefix, body)
        });
        let mut request = request("StreamedImageDecryptionKey", "POST", url);
        let request_body = b"\x80\x00\xfechallenge".to_vec();
        request
            .arguments
            .insert("RequestBody".to_string(), Value::Data(request_body.clone()));
        let mut headers = Dictionary::new();
        headers.insert(
            "Content-Type".to_string(),
            Value::String("application/octet-stream".to_string()),
        );
        request.arguments.insert(
            "RequestAdditionalHeaders".to_string(),
            Value::Dictionary(headers),
        );
        let port = request.data_port.unwrap();
        let mut transfer = HttpAssetTransfer::new(
            dialer,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        );
        let task = transfer.prepare(port, &request).unwrap();
        let outcome = task().unwrap();
        let outgoing = http.join().unwrap();
        let boundary = outgoing
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert!(outgoing.starts_with(b"POST /asset HTTP/1.1\r\n"));
        assert_eq!(&outgoing[boundary..], &request_body);
        let (prefix, body) = guest.join().unwrap();
        assert_eq!(u32::from_be_bytes(prefix) as usize, body.len());
        assert!(body.starts_with(b"bplist00"));
        let value = Value::from_reader(std::io::Cursor::new(&body)).unwrap();
        let reply = value.as_dictionary().unwrap();
        assert_eq!(reply["ResponseStatus"].as_unsigned_integer(), Some(200));
        assert_eq!(reply["ResponseBody"].as_data(), Some(&key_body[..]));
        assert_eq!(reply["ResponseBodyDone"].as_boolean(), Some(true));
        assert_eq!(
            reply["ResponseHeaders"].as_dictionary().unwrap()["content-type"].as_string(),
            Some("application/octet-stream")
        );
        assert_eq!(*dialed.lock().unwrap(), vec![port]);
        match outcome {
            BulkOutcome::Served { bytes, blocks, .. } => {
                assert_eq!(bytes, (prefix.len() + body.len()) as u64);
                assert_eq!(blocks, 1);
            }
            other => panic!("expected the HTTP reply served to the guest, received {other:?}"),
        }
    }

    #[test]
    fn asset_redirects_resolve_against_the_verified_service_origin() {
        assert_eq!(
            redirect_url(
                "https://wkms-public.apple.com/fcs-keys/old",
                "../fcs-keys/new"
            )
            .unwrap(),
            "https://wkms-public.apple.com/fcs-keys/new"
        );
        assert_eq!(
            redirect_url(
                "https://wkms.sd.apple.com/request",
                "https://wkms-public.apple.com/key"
            )
            .unwrap(),
            "https://wkms-public.apple.com/key"
        );
    }

    #[test]
    fn wkms_public_key_redirect_resolves_to_the_verified_service_cdn() {
        let current = "https://wkms-public.apple.com/fcs-keys/key-id=";
        let destination = "https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/key-id=";
        assert_eq!(redirect_url(current, destination).unwrap(), destination);
        assert_eq!(
            redirect_url(destination, "../fcs-keys/next-key=").unwrap(),
            "https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/next-key="
        );
    }

    #[test]
    fn url_asset_accepts_the_verified_service_cdn_and_preserves_request_fields() {
        let url = "https://fcs-keys-pub-prod.cdn-apple.com/fcs-keys/key-id=";
        let mut request = request("URLAsset", "GET", url.to_string());
        let mut headers = Dictionary::new();
        headers.insert(
            "Accept".to_string(),
            Value::String("application/octet-stream".to_string()),
        );
        request.arguments.insert(
            "RequestAdditionalHeaders".to_string(),
            Value::Dictionary(headers),
        );
        let asset = asset_request(&request).unwrap();
        assert_eq!(asset.method, "GET");
        assert_eq!(asset.url, url);
        assert_eq!(asset.headers, vec![("Accept", "application/octet-stream")]);
    }

    #[test]
    fn post_redirect_to_the_same_url_completes_a_get_response() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}/key", listener.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in [
                &b"HTTP/1.1 303 See Other\r\nLocation: /key\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"[..],
                &b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nkey"[..],
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut received = Vec::new();
                let mut byte = [0u8; 1];
                while !received.ends_with(b"\r\n\r\n") {
                    stream.read_exact(&mut byte).unwrap();
                    received.push(byte[0]);
                }
                let header = String::from_utf8(received.clone()).unwrap();
                let length = header.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("Content-Length").then(|| value.trim().parse::<usize>().unwrap())
                }).unwrap_or(0);
                let offset = received.len();
                received.resize(offset + length, 0);
                stream.read_exact(&mut received[offset..]).unwrap();
                stream.write_all(response).unwrap();
                requests.push(received);
            }
            requests
        });
        let mut request = request("StreamedImageDecryptionKey", "POST", url);
        request
            .arguments
            .insert("RequestBody".to_string(), Value::Data(b"req".to_vec()));
        let mut headers = Dictionary::new();
        headers.insert("Content-Length".to_string(), Value::String("3".to_string()));
        headers.insert(
            "Content-Type".to_string(),
            Value::String("application/octet-stream".to_string()),
        );
        request.arguments.insert(
            "RequestAdditionalHeaders".to_string(),
            Value::Dictionary(headers),
        );
        let response = fetch_asset_response_with_cancellation(
            &request,
            &Arc::new(AtomicBool::new(false)),
            &Arc::new(AtomicBool::new(false)),
        )
        .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with(b"POST /key HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /key HTTP/1.1\r\n"));
        assert_eq!(response["ResponseBody"].as_data(), Some(&b"key"[..]));
        assert_eq!(response["ResponseStatus"].as_unsigned_integer(), Some(200));
    }

    #[test]
    fn redirect_headers_preserve_origin_credentials_and_service_metadata() {
        let current = reqwest::Url::parse("https://wkms.sd.apple.com/request").unwrap();
        let next = reqwest::Url::parse("https://wkms.sd.apple.com/key").unwrap();
        let headers = vec![
            ("Authorization", "Bearer session"),
            ("Cookie", "session=restore"),
            ("Content-Length", "3"),
            ("Content-Type", "application/octet-stream"),
            ("X-WKMS-Session", "restore-session"),
        ];
        let mut same_origin = headers.clone();
        redirect_headers(&mut same_origin, &current, &next, false);
        assert_eq!(same_origin, headers);
        let next_origin = reqwest::Url::parse("https://wkms-public.apple.com/key").unwrap();
        let mut next_origin_headers = headers.clone();
        redirect_headers(&mut next_origin_headers, &current, &next_origin, false);
        assert_eq!(
            next_origin_headers,
            vec![
                ("Content-Length", "3"),
                ("Content-Type", "application/octet-stream"),
                ("X-WKMS-Session", "restore-session"),
            ]
        );
        redirect_headers(&mut same_origin, &current, &next, true);
        assert_eq!(
            same_origin,
            vec![
                ("Authorization", "Bearer session"),
                ("Cookie", "session=restore"),
                ("X-WKMS-Session", "restore-session"),
            ]
        );
    }

    #[test]
    fn operator_stop_keeps_its_typed_restore_reason() {
        let error = cancelled(&AtomicBool::new(true), &AtomicBool::new(false)).unwrap_err();
        match error {
            ProviderError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert_eq!(
                    DialCancellation::from_io_error(&error),
                    Some(DialCancellation::OperatorStopped)
                );
            }
            error => panic!("expected typed operator cancellation, received {error}"),
        }
    }

    #[test]
    fn active_http_request_reports_transfer_cancellation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://{}/key", listener.local_addr().unwrap());
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = [0u8; 1];
            stream.read_exact(&mut received).unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        let cancel = Arc::new(AtomicBool::new(false));
        let task_cancel = Arc::clone(&cancel);
        let task = std::thread::spawn(move || {
            fetch_asset_response_with_cancellation(
                &request("URLAsset", "GET", url),
                &Arc::new(AtomicBool::new(false)),
                &task_cancel,
            )
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancel.store(true, Ordering::Release);
        let error = task.join().unwrap().unwrap_err();
        release_tx.send(()).unwrap();
        server.join().unwrap();
        match error {
            ProviderError::Io(error) => {
                assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
                assert_eq!(
                    DialCancellation::from_io_error(&error),
                    Some(DialCancellation::TransferFailed)
                );
            }
            error => panic!("expected typed transfer cancellation, received {error}"),
        }
    }
}
