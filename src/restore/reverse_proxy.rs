use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use plist::{Dictionary, Value};

use crate::usbmux::{
    BulkTransport, MuxReadPolicy, MuxStream, SharedLink, is_device_gone,
    is_host_initiated_teardown, is_run_stopped,
};

use super::report::{SharedReporter, report};
use super::seal_server::{SealServer, is_service_destination};

pub const FDR_PROXY_PREFIX: &str = "[fdr-proxy]";

pub const CTRL_PORT: u16 = 1082;

pub const CTRL_PROTO_VERSION: i64 = 2;

const BEGIN_CTRL: &[u8] = b"BeginCtrl\0";

const HELLO_CONN: &[u8] = b"HelloConn\0";

const LENGTH_PREFIX_LEN: usize = 4;

const MAX_DICTIONARY_LEN: usize = 1024 * 1024;

const CONN_WAKEUP: u32 = 1;

const CTRL_READ_POLL: Duration = Duration::from_secs(30);

const CONN_READ_POLL: Duration = Duration::from_secs(10);

const DIAL_TIMEOUT: Duration = Duration::from_secs(3);

const DIAL_WINDOW: Duration = Duration::from_secs(60);

const DIAL_RETRY: Duration = Duration::from_secs(1);

const CONN_DIAL_TIMEOUT: Duration = Duration::from_secs(6);

const CONN_DEADLINE: Duration = Duration::from_nanos(0x0002_540b_e400);

const PING_MARKER: [u8; 2] = [0xaa, 0xbb];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksRequest {
    pub version: u8,
    pub host: String,
    pub port: u16,
}

pub struct ReverseProxyHandle {
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ReverseProxyHandle {
    pub fn stop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ReverseProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn spawn<T>(
    link: SharedLink<T>,
    stop: Arc<AtomicBool>,
    reporter: SharedReporter,
    armed_at_secs: f64,
    seal: Option<Arc<SealServer>>,
) -> ReverseProxyHandle
where
    T: BulkTransport + Send + 'static,
{
    let cancel = Arc::new(AtomicBool::new(false));
    let thread_cancel = Arc::clone(&cancel);
    let run_stop = Arc::clone(&stop);
    let thread = thread::spawn(move || {
        run_ctrl(link, run_stop, thread_cancel, reporter, armed_at_secs, seal);
    });
    ReverseProxyHandle {
        cancel,
        thread: Some(thread),
    }
}

fn stopped(run: &AtomicBool, cancel: &AtomicBool) -> bool {
    run.load(Ordering::Relaxed) || cancel.load(Ordering::Relaxed)
}

fn run_ctrl<T>(
    link: SharedLink<T>,
    run_stop: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    reporter: SharedReporter,
    armed_at_secs: f64,
    seal: Option<Arc<SealServer>>,
) where
    T: BulkTransport + Send + 'static,
{
    let began = Instant::now();
    let mut ctrl = match dial_ctrl(&link, &run_stop, &cancel, &reporter, armed_at_secs, began) {
        Some(stream) => stream,
        None => return,
    };

    let conn_port = match handshake_ctrl(&mut ctrl) {
        Ok(port) => port,
        Err(error) => {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=ctrl-handshake-failed port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s meaning=\"the ctrl handshake did not complete, so PurpleReverseProxy will keep telling every on-device client that the proxy is not online and fdr_recover will fail with 'Failed to copy proxy information and proxy is enabled.'\" detail=\"{error}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "ctrl-handshake-failed", &line);
            return;
        }
    };
    let line = format!(
        "{FDR_PROXY_PREFIX} result=ctrl-established port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s conn_port={conn_port} meaning=\"the daemon accepted the ctrl handshake and can now accept socks connections; expect it to log 'got a ctrl connection from a host so we can now accept socks connections' and to answer every RPRegisterForAvailability with online\" detail=\"the connection stays open for the whole restore and carries one four byte wake up per proxied connection\"",
        began.elapsed().as_secs_f64()
    );
    report(&reporter, "ctrl-established", &line);

    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let mut wakeups: u64 = 0;
    let mut opened: u64 = 0;
    loop {
        if stopped(&run_stop, &cancel) {
            break;
        }
        let mut word = [0u8; 4];
        match ctrl.read_exact(&mut word) {
            Ok(()) => {}
            Err(error) => {
                let text = error.to_string();
                let (result, meaning) = if is_run_stopped(&text) || stopped(&run_stop, &cancel) {
                    (
                        "ctrl-run-stopped",
                        "the run was stopped while the ctrl connection was parked; the guest neither failed nor went away",
                    )
                } else if is_device_gone(&text) {
                    (
                        "ctrl-guest-left-the-bus",
                        "the device left the bus with the ctrl connection open, which ends it the same way it ends every other session",
                    )
                } else if is_host_initiated_teardown(&text) {
                    (
                        "ctrl-host-timeout",
                        "the host ended the ctrl connection on a bound of its own, which this session is not supposed to have",
                    )
                } else if error.kind() == io::ErrorKind::UnexpectedEof {
                    (
                        "ctrl-closed",
                        "the daemon closed the ctrl connection; it does that when it is going away, and every proxied connection goes with it",
                    )
                } else {
                    (
                        "ctrl-read-failed",
                        "the ctrl connection failed while parked waiting for the guest to ask for a proxied connection",
                    )
                };
                let line = format!(
                    "{FDR_PROXY_PREFIX} result={result} port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s wakeups={wakeups} meaning=\"{meaning}\" detail=\"{text}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, result, &line);
                break;
            }
        }
        let value = u32::from_le_bytes(word);
        wakeups += 1;
        if value != CONN_WAKEUP {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=ctrl-unknown-wakeup port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={elapsed:.3}s value=0x{value:08x} meaning=\"the daemon wrote something on the ctrl connection that is not the four byte 1 it writes for a new proxied connection; the host does not act on it\" detail=\"wakeups={wakeups}\"",
                elapsed = began.elapsed().as_secs_f64()
            );
            report(&reporter, "ctrl-unknown-wakeup", &line);
            continue;
        }
        let index = opened;
        opened += 1;
        let worker_link = link.clone();
        let worker_reporter = Arc::clone(&reporter);
        let worker_run_stop = Arc::clone(&run_stop);
        let worker_cancel = Arc::clone(&cancel);
        let worker_seal = seal.clone();
        workers.push(thread::spawn(move || {
            run_conn(
                worker_link,
                conn_port,
                index,
                worker_run_stop,
                worker_cancel,
                worker_reporter,
                armed_at_secs,
                worker_seal,
            );
        }));
        workers.retain(|worker| !worker.is_finished());
    }

    cancel.store(true, Ordering::Relaxed);
    let _ = ctrl.close();
    for worker in workers {
        let _ = worker.join();
    }
    let line = format!(
        "{FDR_PROXY_PREFIX} result=ctrl-ended port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s wakeups={wakeups} connections={opened} meaning=\"the reverse proxy is down; from here every on-device client is told the proxy is not online again\" detail=\"\"",
        began.elapsed().as_secs_f64()
    );
    report(&reporter, "ctrl-ended", &line);
}

fn dial_ctrl<T>(
    link: &SharedLink<T>,
    run_stop: &Arc<AtomicBool>,
    cancel: &Arc<AtomicBool>,
    reporter: &SharedReporter,
    armed_at_secs: f64,
    began: Instant,
) -> Option<MuxStream<T>>
where
    T: BulkTransport + Send + 'static,
{
    let deadline = Instant::now() + DIAL_WINDOW;
    let mut attempts: u32 = 0;
    let mut last;
    loop {
        if stopped(run_stop, cancel) {
            return None;
        }
        attempts += 1;
        match link.open(CTRL_PORT, DIAL_TIMEOUT) {
            Ok(stream) => {
                let line = format!(
                    "{FDR_PROXY_PREFIX} result=ctrl-dialled port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s attempts={attempts} local={} meaning=\"the guest's mux connected to 127.0.0.1:1082, which is launchd's own listening socket, so PurpleReverseProxy is being spawned now if it was not already running\" detail=\"the daemon takes several seconds to check its sockets in on a cold start, which is why this is dialled at the head of the restore rather than when fdr_recover asks\"",
                    began.elapsed().as_secs_f64(),
                    stream.local_port()
                );
                report(reporter, "ctrl-dialled", &line);
                return Some(
                    stream
                        .with_read_policy(MuxReadPolicy::retrying(CTRL_READ_POLL))
                        .with_cancel(Arc::clone(cancel)),
                );
            }
            Err(error) => {
                last = error.to_string();
                if Instant::now() >= deadline {
                    break;
                }
                thread::sleep(DIAL_RETRY);
            }
        }
    }
    let line = format!(
        "{FDR_PROXY_PREFIX} result=ctrl-no-session port={CTRL_PORT} at={armed_at_secs:.3}s elapsed={:.3}s attempts={attempts} meaning=\"guest port 1082 never accepted, so PurpleReverseProxy has no host and fdr_recover will fail with 'Failed to copy proxy information and proxy is enabled.'; check that the ramdisk carries com.apple.PurpleReverseProxy.ramdisk.plist and that its ctrl socket is reachable at 127.0.0.1:1082\" detail=\"{last}\"",
        began.elapsed().as_secs_f64()
    );
    report(reporter, "ctrl-no-session", &line);
    None
}

fn handshake_ctrl<T>(ctrl: &mut MuxStream<T>) -> Result<u16, ProxyError>
where
    T: BulkTransport,
{
    ctrl.write_all(BEGIN_CTRL)?;
    ctrl.flush()?;

    let mut request = Dictionary::new();
    request.insert(
        "Command".to_string(),
        Value::String("BeginCtrl".to_string()),
    );
    request.insert(
        "CtrlProtoVersion".to_string(),
        Value::Integer(CTRL_PROTO_VERSION.into()),
    );
    write_dictionary(ctrl, &request)?;

    let reply = read_dictionary(ctrl)?;
    let conn_port = reply
        .get("ConnPort")
        .and_then(Value::as_signed_integer)
        .ok_or(ProxyError::MissingConnPort)?;
    u16::try_from(conn_port).map_err(|_| ProxyError::ConnPortOutOfRange { value: conn_port })
}

#[allow(clippy::too_many_arguments)]
fn run_conn<T>(
    link: SharedLink<T>,
    conn_port: u16,
    index: u64,
    run_stop: Arc<AtomicBool>,
    cancel: Arc<AtomicBool>,
    reporter: SharedReporter,
    armed_at_secs: f64,
    seal: Option<Arc<SealServer>>,
) where
    T: BulkTransport + Send + 'static,
{
    let began = Instant::now();
    if stopped(&run_stop, &cancel) {
        return;
    }
    let mut conn = match link.open(conn_port, CONN_DIAL_TIMEOUT) {
        Ok(stream) => stream
            .with_read_policy(MuxReadPolicy::retrying(CONN_READ_POLL))
            .with_cancel(Arc::clone(&cancel)),
        Err(error) => {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=conn-no-session port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} meaning=\"the guest asked for a proxied connection and the host could not open one to the port the daemon published; the daemon waits {:.3}s for it and then drops the socks client\" detail=\"{error}\"",
                began.elapsed().as_secs_f64(),
                CONN_DEADLINE.as_secs_f64()
            );
            report(&reporter, "conn-no-session", &line);
            return;
        }
    };

    let identifier = match handshake_conn(&mut conn) {
        Ok(identifier) => identifier,
        Err(error) => {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=conn-handshake-failed port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} meaning=\"the conn handshake did not complete, so the guest's socks client is left with a connection that carries nothing\" detail=\"{error}\"",
                began.elapsed().as_secs_f64()
            );
            report(&reporter, "conn-handshake-failed", &line);
            return;
        }
    };

    let mut opening = [0u8; 2];
    if let Err(error) = conn.read_exact(&mut opening) {
        let line = format!(
            "{FDR_PROXY_PREFIX} result=conn-silent port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} identifier={identifier} meaning=\"the conn handshake completed and then the guest sent nothing; the daemon pumps this connection raw, so whatever its socks client wrote should have arrived here\" detail=\"{error}\"",
            began.elapsed().as_secs_f64()
        );
        report(&reporter, "conn-silent", &line);
        return;
    }

    if opening == PING_MARKER {
        match answer_ping(&mut conn) {
            Ok(()) => {
                let line = format!(
                    "{FDR_PROXY_PREFIX} result=ping-answered port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} identifier={identifier} meaning=\"this was libReverseProxyDevice pinging the host through the daemon, not a proxied request; the host answered Pong with a real CFBoolean, which is what copyProxyDictionaryForURL compares against kCFBooleanTrue by pointer\" detail=\"without this answer libFDR gets a NULL proxy dictionary and raises the same 'Failed to copy proxy information and proxy is enabled.' as a host that never connected\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "ping-answered", &line);
            }
            Err(error) => {
                let line = format!(
                    "{FDR_PROXY_PREFIX} result=ping-failed port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} identifier={identifier} meaning=\"the host ping could not be answered, so copyProxyDictionaryForURL will return NULL and fdr_recover fails exactly as it did with no host at all\" detail=\"{error}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "ping-failed", &line);
            }
        }
        let _ = conn.close();
        return;
    }

    let request = match read_socks_request(&mut conn, opening) {
        Ok(request) => request,
        Err(error) => {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=socks-unreadable port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} identifier={identifier} opening=0x{:02x}{:02x} meaning=\"the bytes the guest sent on the proxied connection are neither a host ping nor a supported SOCKS request; the host is the SOCKS server on this connection and everything after the conn handshake is the guest's own client\" detail=\"{error}\"",
                began.elapsed().as_secs_f64(),
                opening[0],
                opening[1]
            );
            report(&reporter, "socks-unreadable", &line);
            return;
        }
    };

    let line = format!(
        "{FDR_PROXY_PREFIX} result=socks-request port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} identifier={identifier} socks_version={} target={}:{} meaning=\"this is what fdr_recover wants reached; the request left the guest, which is the thing that never happened before\" detail=\"\"",
        began.elapsed().as_secs_f64(),
        request.version,
        request.host,
        request.port
    );
    report(&reporter, "socks-request", &line);

    if let Some(server) = seal
        .as_deref()
        .filter(|_| is_service_destination(&request.host, request.port))
    {
        if let Err(error) = grant_socks(&mut conn, &request) {
            let line = format!(
                "{FDR_PROXY_PREFIX} result=socks-grant-failed port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} target={}:{} meaning=\"the host accepted the guest's SOCKS request for its local FDR service and could not write the acceptance, so the guest's client times out rather than getting an answer\" detail=\"{error}\"",
                began.elapsed().as_secs_f64(),
                request.host,
                request.port
            );
            report(&reporter, "socks-grant-failed", &line);
            let _ = conn.close();
            return;
        }
        let line = format!(
            "{FDR_PROXY_PREFIX} result=socks-granted port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} target={}:{} meaning=\"this destination is the host's offline FDR service, so the SOCKS request was accepted and the host now speaks HTTP on this connection as the certificate authority and sealing server the guest asked for\" detail=\"nothing here reaches the internet and nothing here disables the guest's FDR check; the host answers it under keys it genuinely holds, and every signed digest comes out of a manifest the guest itself sent\"",
            began.elapsed().as_secs_f64(),
            request.host,
            request.port
        );
        report(&reporter, "socks-granted", &line);

        match server.serve(&mut conn) {
            Ok(outcome) => {
                let line = format!(
                    "{FDR_PROXY_PREFIX} result=fdr-served port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} outcome={outcome:?} meaning=\"the host read one FDR request off this proxied connection and answered it; the {} line for this exchange says what was issued or signed\" detail=\"\"",
                    began.elapsed().as_secs_f64(),
                    crate::restore::seal_server::FDR_SEAL_PREFIX
                );
                report(&reporter, "fdr-served", &line);
            }
            Err(error) => {
                let line = format!(
                    "{FDR_PROXY_PREFIX} result=fdr-unserved port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} meaning=\"the guest reached the local FDR service and the host could not read or answer the request on this connection; nothing was invented to fill it, so the guest fails on the reason named here\" detail=\"{error}\"",
                    began.elapsed().as_secs_f64()
                );
                report(&reporter, "fdr-unserved", &line);
            }
        }
        let _ = conn.close();
        return;
    }

    if let Err(error) = refuse_socks(&mut conn, &request) {
        let line = format!(
            "{FDR_PROXY_PREFIX} result=socks-refusal-failed port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} meaning=\"the refusal could not be written, so the guest's socks client will time out rather than fail\" detail=\"{error}\"",
            began.elapsed().as_secs_f64()
        );
        report(&reporter, "socks-refusal-failed", &line);
    } else {
        let line = format!(
            "{FDR_PROXY_PREFIX} result=socks-refused port={conn_port} at={armed_at_secs:.3}s elapsed={:.3}s connection={index} target={}:{} meaning=\"the host answered the SOCKS request with a refusal because it will not reach the public internet and holds no local server for this destination; fdr_recover now fails on the destination named here rather than on the proxy being absent\" detail=\"nothing here disables the guest's FDR check, it names what the check wants; restored's copy_restore_options whitelist carries FDRCAURL, FDRDataStoreURL, FDRSealingURL and FDRTrustObjectURL, which restored copies into libFDR's CAURL, DSURL and SealingURL at 0x100070964, so a host that means to answer this serves it itself and names its own URL rather than letting the apple.com default stand\"",
            began.elapsed().as_secs_f64(),
            request.host,
            request.port
        );
        report(&reporter, "socks-refused", &line);
    }
    let _ = conn.close();
}

fn handshake_conn<T>(conn: &mut MuxStream<T>) -> Result<String, ProxyError>
where
    T: BulkTransport,
{
    conn.write_all(HELLO_CONN)?;
    conn.flush()?;
    let reply = read_dictionary(conn)?;
    Ok(reply
        .get("Identifier")
        .and_then(Value::as_string)
        .unwrap_or("none")
        .to_string())
}

// `Pong` must be a real boolean: the client compares it against `kCFBooleanTrue` by pointer.
fn answer_ping<S: Read + Write>(conn: &mut S) -> Result<(), ProxyError> {
    let request = read_dictionary(conn)?;
    let command = request.get("Command").and_then(Value::as_string);
    if command != Some("Ping") {
        return Err(ProxyError::UnknownConnCommand {
            command: command.unwrap_or("none").to_string(),
        });
    }
    let mut reply = Dictionary::new();
    reply.insert("Pong".to_string(), Value::Boolean(true));
    write_dictionary(conn, &reply)
}

// Both SOCKS versions are served because `copyProxyDictionaryForURL` sets no version key.
fn read_socks_request<S: Read + Write>(
    conn: &mut S,
    opening: [u8; 2],
) -> Result<SocksRequest, ProxyError> {
    match opening[0] {
        4 => read_socks4_request(conn, opening[1]),
        5 => read_socks5_request(conn, opening[1]),
        other => Err(ProxyError::UnknownSocksVersion { version: other }),
    }
}

fn read_socks5_request<S: Read + Write>(
    conn: &mut S,
    count: u8,
) -> Result<SocksRequest, ProxyError> {
    let mut methods = vec![0u8; count as usize];
    if !methods.is_empty() {
        conn.read_exact(&mut methods)?;
    }
    if !methods.contains(&0x00) {
        conn.write_all(&[0x05, 0xff])?;
        conn.flush()?;
        return Err(ProxyError::NoAcceptableSocksMethod);
    }
    conn.write_all(&[0x05, 0x00])?;
    conn.flush()?;

    let mut head = [0u8; 4];
    conn.read_exact(&mut head)?;
    if head[0] != 5 {
        return Err(ProxyError::UnknownSocksVersion { version: head[0] });
    }
    if head[1] != 0x01 {
        return Err(ProxyError::UnsupportedSocksCommand { command: head[1] });
    }
    let host = match head[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            conn.read_exact(&mut octets)?;
            Ipv4Addr::from(octets).to_string()
        }
        0x03 => {
            let mut length = [0u8; 1];
            conn.read_exact(&mut length)?;
            let mut name = vec![0u8; length[0] as usize];
            conn.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        0x04 => {
            let mut octets = [0u8; 16];
            conn.read_exact(&mut octets)?;
            Ipv6Addr::from(octets).to_string()
        }
        other => return Err(ProxyError::UnknownSocksAddressType { kind: other }),
    };
    let mut port = [0u8; 2];
    conn.read_exact(&mut port)?;
    Ok(SocksRequest {
        version: 5,
        host,
        port: u16::from_be_bytes(port),
    })
}

fn read_socks4_request<S: Read + Write>(
    conn: &mut S,
    command: u8,
) -> Result<SocksRequest, ProxyError> {
    if command != 0x01 {
        return Err(ProxyError::UnsupportedSocksCommand { command });
    }
    let mut head = [0u8; 6];
    conn.read_exact(&mut head)?;
    let port = u16::from_be_bytes([head[0], head[1]]);
    let address = [head[2], head[3], head[4], head[5]];
    let _user = read_cstring(conn)?;
    let host = if address[0] == 0 && address[1] == 0 && address[2] == 0 && address[3] != 0 {
        read_cstring(conn)?
    } else {
        Ipv4Addr::from(address).to_string()
    };
    Ok(SocksRequest {
        version: 4,
        host,
        port,
    })
}

fn read_cstring<S: Read>(conn: &mut S) -> Result<String, ProxyError> {
    let mut out = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        conn.read_exact(&mut byte)?;
        if byte[0] == 0 {
            return Ok(String::from_utf8_lossy(&out).into_owned());
        }
        if out.len() >= 255 {
            return Err(ProxyError::SocksStringTooLong);
        }
        out.push(byte[0]);
    }
}

fn grant_socks<S: Write>(conn: &mut S, request: &SocksRequest) -> io::Result<()> {
    match request.version {
        5 => conn.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?,
        _ => conn.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0])?,
    }
    conn.flush()
}

fn refuse_socks<S: Write>(conn: &mut S, request: &SocksRequest) -> io::Result<()> {
    match request.version {
        5 => conn.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])?,
        _ => conn.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0])?,
    }
    conn.flush()
}

fn write_dictionary<W: Write>(writer: &mut W, dictionary: &Dictionary) -> Result<(), ProxyError> {
    let mut body = Vec::new();
    Value::Dictionary(dictionary.clone()).to_writer_binary(&mut body)?;
    if body.len() > MAX_DICTIONARY_LEN {
        return Err(ProxyError::DictionaryTooLarge {
            announced: body.len() as u64,
        });
    }
    // Host order, not network order: the daemon applies no byte swap, so this is not the ramrod big-endian framing and `crate::ramrod::codec` must not be reused here.
    let prefix = (body.len() as u32).to_le_bytes();
    let mut framed = Vec::with_capacity(LENGTH_PREFIX_LEN + body.len());
    framed.extend_from_slice(&prefix);
    framed.append(&mut body);
    writer.write_all(&framed)?;
    writer.flush()?;
    Ok(())
}

fn read_dictionary<R: Read>(reader: &mut R) -> Result<Dictionary, ProxyError> {
    let mut prefix = [0u8; LENGTH_PREFIX_LEN];
    reader.read_exact(&mut prefix)?;
    let announced = u32::from_le_bytes(prefix) as u64;
    if announced == 0 {
        return Err(ProxyError::EmptyDictionary);
    }
    if announced > MAX_DICTIONARY_LEN as u64 {
        return Err(ProxyError::DictionaryTooLarge { announced });
    }
    let mut body = vec![0u8; announced as usize];
    reader.read_exact(&mut body)?;
    match Value::from_reader(io::Cursor::new(body))? {
        Value::Dictionary(dictionary) => Ok(dictionary),
        other => Err(ProxyError::NotADictionary {
            found: value_kind(&other),
        }),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Array(_) => "array",
        Value::Boolean(_) => "boolean",
        Value::Data(_) => "data",
        Value::Date(_) => "date",
        Value::Dictionary(_) => "dictionary",
        Value::Real(_) => "real",
        Value::Integer(_) => "integer",
        Value::String(_) => "string",
        Value::Uid(_) => "uid",
        _ => "unknown",
    }
}

#[derive(Debug)]
pub enum ProxyError {
    Io(io::Error),
    Plist(plist::Error),
    MissingConnPort,
    ConnPortOutOfRange { value: i64 },
    EmptyDictionary,
    DictionaryTooLarge { announced: u64 },
    NotADictionary { found: &'static str },
    UnknownSocksVersion { version: u8 },
    UnsupportedSocksCommand { command: u8 },
    UnknownSocksAddressType { kind: u8 },
    NoAcceptableSocksMethod,
    SocksStringTooLong,
    UnknownConnCommand { command: String },
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Plist(error) => write!(formatter, "property list: {error}"),
            Self::MissingConnPort => write!(
                formatter,
                "the daemon's ctrl reply carried no ConnPort, so no proxied connection can be opened"
            ),
            Self::ConnPortOutOfRange { value } => write!(
                formatter,
                "the daemon published ConnPort {value}, which is not a TCP port"
            ),
            Self::EmptyDictionary => {
                write!(formatter, "a dictionary was announced as zero bytes")
            }
            Self::DictionaryTooLarge { announced } => write!(
                formatter,
                "a dictionary was announced as {announced} bytes, past the {MAX_DICTIONARY_LEN} byte bound"
            ),
            Self::NotADictionary { found } => write!(
                formatter,
                "the property list on the wire was a {found}, not a dictionary"
            ),
            Self::UnknownSocksVersion { version } => write!(
                formatter,
                "the guest's client opened with SOCKS version {version}"
            ),
            Self::UnsupportedSocksCommand { command } => write!(
                formatter,
                "the guest's client asked for SOCKS command 0x{command:02x}, and only CONNECT is served"
            ),
            Self::UnknownSocksAddressType { kind } => write!(
                formatter,
                "the guest's client named its destination with address type 0x{kind:02x}"
            ),
            Self::NoAcceptableSocksMethod => write!(
                formatter,
                "the guest's client offered no authentication method, and the host offers only none"
            ),
            Self::SocksStringTooLong => {
                write!(formatter, "a NUL terminated SOCKS field ran past 255 bytes")
            }
            Self::UnknownConnCommand { command } => write!(
                formatter,
                "a proxied connection opened with the host ping marker and then carried command {command}, and only Ping is answered"
            ),
        }
    }
}

impl std::error::Error for ProxyError {}

impl From<io::Error> for ProxyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<plist::Error> for ProxyError {
    fn from(error: plist::Error) -> Self {
        Self::Plist(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pipe {
        inbound: io::Cursor<Vec<u8>>,
        outbound: Vec<u8>,
    }

    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            self.inbound.read(out)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.outbound.write(data)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(dictionary: &Dictionary) -> Vec<u8> {
        let mut body = Vec::new();
        Value::Dictionary(dictionary.clone())
            .to_writer_binary(&mut body)
            .expect("binary plist");
        let mut framed = (body.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    #[test]
    fn dictionary_framing_is_a_host_order_prefix_over_a_binary_body() {
        let mut dictionary = Dictionary::new();
        dictionary.insert(
            "Command".to_string(),
            Value::String("BeginCtrl".to_string()),
        );
        let mut pipe = Pipe {
            inbound: io::Cursor::new(Vec::new()),
            outbound: Vec::new(),
        };
        write_dictionary(&mut pipe, &dictionary).expect("write");
        let announced = u32::from_le_bytes([
            pipe.outbound[0],
            pipe.outbound[1],
            pipe.outbound[2],
            pipe.outbound[3],
        ]) as usize;
        assert_eq!(announced, pipe.outbound.len() - LENGTH_PREFIX_LEN);
        assert_eq!(
            &pipe.outbound[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + 8],
            b"bplist00"
        );
    }

    #[test]
    fn a_written_dictionary_reads_back() {
        let mut dictionary = Dictionary::new();
        dictionary.insert("ConnPort".to_string(), Value::Integer(49154.into()));
        let bytes = framed(&dictionary);
        let mut reader = io::Cursor::new(bytes);
        let read = read_dictionary(&mut reader).expect("read");
        assert_eq!(
            read.get("ConnPort").and_then(Value::as_signed_integer),
            Some(49154)
        );
    }

    #[test]
    fn a_body_larger_than_the_bound_is_refused_before_it_is_allocated() {
        let mut bytes = ((MAX_DICTIONARY_LEN as u32) + 1).to_le_bytes().to_vec();
        bytes.extend_from_slice(b"bplist00");
        let mut reader = io::Cursor::new(bytes);
        let error = read_dictionary(&mut reader).expect_err("bounded");
        assert!(matches!(error, ProxyError::DictionaryTooLarge { .. }));
    }

    #[test]
    fn the_ctrl_opening_carries_its_terminator() {
        assert_eq!(BEGIN_CTRL.len(), 10);
        assert_eq!(BEGIN_CTRL[9], 0);
        assert_eq!(HELLO_CONN.len(), 10);
        assert_eq!(HELLO_CONN[9], 0);
    }

    #[test]
    fn the_wakeup_is_read_in_host_order() {
        assert_eq!(u32::from_le_bytes([1, 0, 0, 0]), CONN_WAKEUP);
    }

    #[test]
    fn the_pong_answer_carries_a_real_boolean() {
        let mut reply = Dictionary::new();
        reply.insert("Pong".to_string(), Value::Boolean(true));
        let mut pipe = Pipe {
            inbound: io::Cursor::new(Vec::new()),
            outbound: Vec::new(),
        };
        write_dictionary(&mut pipe, &reply).expect("write");
        let body = &pipe.outbound[LENGTH_PREFIX_LEN..];
        assert_eq!(&body[0..8], b"bplist00");
        let name = body
            .windows(5)
            .position(|window| window == b"\x54Pong")
            .expect("the key is on the wire");
        assert_eq!(body[name + 5], 0x09, "the value must be the boolean marker");
    }

    #[test]
    fn the_ping_marker_is_not_a_socks_opening() {
        assert_ne!(PING_MARKER[0], 4);
        assert_ne!(PING_MARKER[0], 5);
    }

    #[test]
    fn a_socks5_connect_to_a_named_host_is_read() {
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
        let host = b"gg.apple.com";
        bytes.push(host.len() as u8);
        bytes.extend_from_slice(host);
        bytes.extend_from_slice(&443u16.to_be_bytes());
        let mut pipe = Pipe {
            inbound: io::Cursor::new(bytes),
            outbound: Vec::new(),
        };
        let request = read_socks5_request(&mut pipe, 1).expect("read");
        assert_eq!(
            request,
            SocksRequest {
                version: 5,
                host: "gg.apple.com".to_string(),
                port: 443,
            }
        );
        assert_eq!(pipe.outbound, vec![0x05, 0x00]);
    }

    #[test]
    fn a_socks4a_connect_to_a_named_host_is_read() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&80u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 1]);
        bytes.extend_from_slice(b"host\0");
        bytes.extend_from_slice(b"gg.apple.com\0");
        let mut pipe = Pipe {
            inbound: io::Cursor::new(bytes),
            outbound: Vec::new(),
        };
        let request = read_socks4_request(&mut pipe, 0x01).expect("read");
        assert_eq!(
            request,
            SocksRequest {
                version: 4,
                host: "gg.apple.com".to_string(),
                port: 80,
            }
        );
    }
}
