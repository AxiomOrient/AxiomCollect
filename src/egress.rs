use std::io;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::domain::{Failure, FailureCode, NetworkPolicy};
use crate::policy::{parse_url, validate_and_resolve};

const MAX_PROXY_HEADER_BYTES: usize = 64 * 1024;
const PROXY_IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Longest a relayed connection may stall without either side producing a byte.
/// The parent's wall budget still bounds the whole session; this stops one idle
/// upstream from holding a proxy task and its operation slot until then.
const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on proxy connections served at once. A connection only charges the
/// operation budget after its header is read, so without this a page could park an
/// unbounded number of tasks in that pre-reservation window.
const MAX_CONCURRENT_PROXY_CLIENTS: usize = 64;

/// A proxy-side rejection, carrying the typed reason rather than only its text.
#[derive(Debug, Clone)]
pub struct EgressFatal {
    pub code: FailureCode,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct EgressStats {
    /// Number of public upstream TCP connections opened by the proxy. HTTPS is
    /// opaque after CONNECT, so one connection may carry several browser HTTP
    /// requests; this is intentionally a connection-budget unit, not a request
    /// counter.
    pub connection_operations: u32,
    pub transferred_bytes: usize,
    pub fatal_error: Option<EgressFatal>,
}

#[derive(Debug)]
struct SharedStats {
    connection_operations: AtomicU32,
    transferred_bytes: AtomicUsize,
    fatal_error: Mutex<Option<EgressFatal>>,
    max_connections: u32,
    max_transferred_bytes: usize,
}

pub struct EgressProxy {
    endpoint: String,
    cancellation: CancellationToken,
    task: Option<JoinHandle<()>>,
    stats: Arc<SharedStats>,
}

impl EgressProxy {
    pub async fn start(
        max_connections: u32,
        max_transferred_bytes: usize,
    ) -> Result<Self, Failure> {
        if max_connections == 0 || max_transferred_bytes == 0 {
            return Err(Failure::new(
                FailureCode::BudgetExhausted,
                "no egress proxy budget remains",
            ));
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|error| {
            Failure::new(
                FailureCode::InternalError,
                format!("failed to bind the egress proxy: {error}"),
            )
        })?;
        let address = listener.local_addr().map_err(|error| {
            Failure::new(
                FailureCode::InternalError,
                format!("failed to inspect the egress proxy address: {error}"),
            )
        })?;
        let cancellation = CancellationToken::new();
        let stats = Arc::new(SharedStats {
            connection_operations: AtomicU32::new(0),
            transferred_bytes: AtomicUsize::new(0),
            fatal_error: Mutex::new(None),
            max_connections,
            max_transferred_bytes,
        });
        let task = tokio::spawn(serve(listener, stats.clone(), cancellation.clone()));
        Ok(Self {
            endpoint: format!("http://{address}"),
            cancellation,
            task: Some(task),
            stats,
        })
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    #[must_use]
    pub fn stats(&self) -> EgressStats {
        EgressStats {
            connection_operations: self.stats.connection_operations.load(Ordering::Relaxed),
            transferred_bytes: self.stats.transferred_bytes.load(Ordering::Relaxed),
            fatal_error: self
                .stats
                .fatal_error
                .lock()
                .ok()
                .and_then(|value| value.clone()),
        }
    }

    pub async fn shutdown(mut self) -> EgressStats {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        // The serving task owns the client join set. Snapshot only after it has
        // finished so the final relay/accounting updates are visible to the caller.
        self.stats()
    }
}

impl Drop for EgressProxy {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(listener: TcpListener, stats: Arc<SharedStats>, cancellation: CancellationToken) {
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            accepted = listener.accept(), if clients.len() < MAX_CONCURRENT_PROXY_CLIENTS => {
                let Ok((stream, _)) = accepted else {
                    record_fatal(&stats, FailureCode::ProviderFailed, "egress proxy accept failed");
                    break;
                };
                clients.spawn(handle_client(stream, stats.clone()));
            }
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    }
    clients.abort_all();
    while clients.join_next().await.is_some() {}
}

async fn handle_client(mut client: TcpStream, stats: Arc<SharedStats>) {
    if let Err(error) = handle_client_inner(&mut client, &stats).await {
        let _ = client.shutdown().await;
        // A malformed or policy-rejected request is a fatal signal for the whole
        // session; a transport-level error on one subresource is not.
        if matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::OutOfMemory
        ) {
            record_fatal(
                &stats,
                FailureCode::PolicyRejected,
                &format!("egress proxy rejected traffic: {error}"),
            );
        }
    }
}

async fn handle_client_inner(client: &mut TcpStream, stats: &SharedStats) -> io::Result<()> {
    let request = tokio::time::timeout(PROXY_IO_TIMEOUT, read_proxy_request(client))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy header timed out"))??;
    let target = proxy_target(&request)?;
    reserve_connection(stats)?;
    let mut upstream = connect_public(&target).await.map_err(|failure| {
        if failure.code == FailureCode::PolicyRejected {
            record_fatal(stats, FailureCode::PolicyRejected, &failure.message);
            io::Error::new(io::ErrorKind::InvalidData, failure.message)
        } else {
            io::Error::new(io::ErrorKind::ConnectionRefused, failure.message)
        }
    })?;

    if request.is_connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if !request.trailing.is_empty() {
            account_bytes(stats, request.trailing.len())?;
            upstream.write_all(&request.trailing).await?;
        }
    } else {
        let outbound = rewrite_http_request(&request, &target)?;
        account_bytes(stats, outbound.len())?;
        upstream.write_all(&outbound).await?;
    }
    relay(client, &mut upstream, stats).await
}

#[derive(Debug)]
struct ProxyRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<String>,
    trailing: Vec<u8>,
    is_connect: bool,
}

async fn read_proxy_request(client: &mut TcpStream) -> io::Result<ProxyRequest> {
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        if bytes.len() >= MAX_PROXY_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy request header exceeds the limit",
            ));
        }
        let previous_len = bytes.len();
        let mut buffer = [0_u8; 4096];
        let remaining = MAX_PROXY_HEADER_BYTES - bytes.len();
        let read_limit = remaining.min(buffer.len());
        let read = client.read(&mut buffer[..read_limit]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy request ended before its header",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        let search_from = previous_len.saturating_sub(3);
        if let Some(position) = bytes[search_from..]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break search_from + position + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "proxy header is not UTF-8"))?;
    let mut lines = header.trim_end_matches("\r\n").split("\r\n");
    let first = lines.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "proxy request line is missing")
    })?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or_default().to_owned();
    let target = parts.next().unwrap_or_default().to_owned();
    let version = parts.next().unwrap_or_default().to_owned();
    if method.is_empty()
        || target.is_empty()
        || !matches!(version.as_str(), "HTTP/1.0" | "HTTP/1.1")
        || parts.next().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy request line is invalid",
        ));
    }
    Ok(ProxyRequest {
        is_connect: method.eq_ignore_ascii_case("CONNECT"),
        method,
        target,
        version,
        headers: lines.map(str::to_owned).collect(),
        trailing: bytes[header_end..].to_vec(),
    })
}

fn proxy_target(request: &ProxyRequest) -> io::Result<Url> {
    if request.is_connect {
        let authority = if request.target.contains(':') {
            request.target.clone()
        } else {
            format!("{}:443", request.target)
        };
        parse_url(&format!("https://{authority}/"))
    } else {
        parse_url(&request.target)
    }
    .map_err(|failure| io::Error::new(io::ErrorKind::InvalidData, failure.message))
}

fn rewrite_http_request(request: &ProxyRequest, target: &Url) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let path = match target.query() {
        Some(query) => format!("{}?{query}", target.path()),
        None => target.path().to_owned(),
    };
    output
        .extend_from_slice(format!("{} {path} {}\r\n", request.method, request.version).as_bytes());
    for header in &request.headers {
        let name = header
            .split_once(':')
            .map(|(name, _)| name.trim())
            .unwrap_or_default();
        if name.eq_ignore_ascii_case("proxy-connection") || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        output.extend_from_slice(header.as_bytes());
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(b"Connection: close\r\n\r\n");
    output.extend_from_slice(&request.trailing);
    Ok(output)
}

async fn connect_public(url: &Url) -> Result<TcpStream, Failure> {
    let target =
        validate_and_resolve(url.clone(), NetworkPolicy::PublicOnly, PROXY_IO_TIMEOUT).await?;
    let started = Instant::now();
    let mut diagnostic = String::new();
    for address in target.addresses {
        let remaining = PROXY_IO_TIMEOUT.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => diagnostic = error.to_string(),
            Err(_) => diagnostic = "connection timed out".to_owned(),
        }
    }
    Err(Failure::new(
        FailureCode::NetworkFailed,
        format!(
            "egress proxy could not connect to {}: {}",
            target.host,
            if diagnostic.is_empty() {
                "no address succeeded"
            } else {
                &diagnostic
            }
        ),
    ))
}

async fn relay(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    stats: &SharedStats,
) -> io::Result<()> {
    let (client_read, client_write) = client.split();
    let (upstream_read, upstream_write) = upstream.split();
    let to_upstream = transfer(client_read, upstream_write, stats);
    let to_client = transfer(upstream_read, client_write, stats);
    tokio::try_join!(to_upstream, to_client)?;
    Ok(())
}

async fn transfer<R, W>(mut reader: R, mut writer: W, stats: &SharedStats) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(PROXY_IDLE_TIMEOUT, reader.read(&mut buffer))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "proxy relay stalled"))??;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        account_bytes(stats, read)?;
        writer.write_all(&buffer[..read]).await?;
    }
}

fn reserve_connection(stats: &SharedStats) -> io::Result<()> {
    stats
        .connection_operations
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            (current < stats.max_connections).then_some(current + 1)
        })
        .map(|_| ())
        .map_err(|_| {
            record_fatal(
                stats,
                FailureCode::BudgetExhausted,
                "external provider connection-operation budget exhausted",
            );
            io::Error::other("connection-operation budget exhausted")
        })
}

fn account_bytes(stats: &SharedStats, bytes: usize) -> io::Result<()> {
    stats
        .transferred_bytes
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current
                .checked_add(bytes)
                .filter(|next| *next <= stats.max_transferred_bytes)
        })
        .map(|_| ())
        .map_err(|_| {
            record_fatal(
                stats,
                FailureCode::BudgetExhausted,
                "external provider byte budget exhausted",
            );
            io::Error::other("external provider byte budget exhausted")
        })
}

/// Records the first proxy-side rejection with its typed reason.
///
/// The parent maps this straight onto a `FailureCode`, so the reason must travel
/// as a value; classifying it by matching on the message text later would break
/// silently the moment a message is reworded.
fn record_fatal(stats: &SharedStats, code: FailureCode, message: &str) {
    if let Ok(mut error) = stats.fatal_error.lock()
        && error.is_none()
    {
        *error = Some(EgressFatal {
            code,
            message: message.to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use url::Url;

    use super::{EgressProxy, ProxyRequest, SharedStats, proxy_target, rewrite_http_request};

    #[test]
    fn absolute_http_request_is_rewritten_to_origin_form() {
        let request = ProxyRequest {
            method: "GET".to_owned(),
            target: "http://example.com/a?q=1".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: vec![
                "Host: example.com".to_owned(),
                "Proxy-Connection: keep-alive".to_owned(),
            ],
            trailing: Vec::new(),
            is_connect: false,
        };
        let target = proxy_target(&request);
        assert!(target.is_ok());
        let bytes = target
            .ok()
            .and_then(|value| rewrite_http_request(&request, &value).ok())
            .unwrap_or_default();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("GET /a?q=1 HTTP/1.1\r\n"));
        assert!(!text.to_ascii_lowercase().contains("proxy-connection"));
    }

    #[test]
    fn connect_authority_becomes_https_target() {
        let request = ProxyRequest {
            method: "CONNECT".to_owned(),
            target: "example.com:443".to_owned(),
            version: "HTTP/1.1".to_owned(),
            headers: Vec::new(),
            trailing: Vec::new(),
            is_connect: true,
        };
        let target = proxy_target(&request);
        assert_eq!(
            target.as_ref().ok().map(Url::as_str),
            Some("https://example.com/")
        );
    }

    #[tokio::test]
    async fn connection_time_resolution_rejects_private_addresses() {
        let proxy = EgressProxy::start(2, 64 * 1024).await;
        assert!(proxy.is_ok());
        let Some(proxy) = proxy.ok() else {
            return;
        };
        let endpoint = proxy.endpoint().trim_start_matches("http://");
        let stream = tokio::net::TcpStream::connect(endpoint).await;
        assert!(stream.is_ok());
        let Some(mut stream) = stream.ok() else {
            return;
        };
        let request = b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n";
        assert!(stream.write_all(request).await.is_ok());
        let mut response = Vec::new();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_to_end(&mut response),
        )
        .await;
        let stats = proxy.shutdown().await;
        assert!(stats.fatal_error.is_some());
        assert_eq!(stats.connection_operations, 1);
    }

    #[tokio::test]
    async fn shutdown_snapshots_stats_after_serving_task_finishes() {
        let cancellation = CancellationToken::new();
        let stats = Arc::new(SharedStats {
            connection_operations: AtomicU32::new(0),
            transferred_bytes: AtomicUsize::new(0),
            fatal_error: Mutex::new(None),
            max_connections: 1,
            max_transferred_bytes: 1024,
        });
        let update = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            update.transferred_bytes.store(17, Ordering::Relaxed);
        });
        let proxy = EgressProxy {
            endpoint: "http://127.0.0.1:1".to_owned(),
            cancellation,
            task: Some(task),
            stats,
        };

        let result = proxy.shutdown().await;

        assert_eq!(result.transferred_bytes, 17);
    }
}
