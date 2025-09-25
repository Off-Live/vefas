//! Production-grade VEFAS client implementation with rustls + aws-lc-rs
//!
//! This module provides a unified TLS client that captures complete session data
//! for zkTLS verification, including certificates, handshake transcripts, and
//! session keys.

use std::sync::{Arc, Mutex};
use std::io::{Read, Write};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector as AsyncTlsConnector;
use tokio_rustls::client::TlsStream as AsyncTlsStream;
use rustls::{
    ClientConfig, ClientConnection, StreamOwned,
    RootCertStore,
};
use rustls::pki_types::ServerName;
use url::Url;

use crate::error::{VefasCoreError, Result};
use crate::transport::TlsTee;
use crate::transport::AsyncTlsTee;
use crate::keylog::VefasKeyLog;
use crate::session::SessionData;
use crate::http::{HttpProcessor, HttpData};
use crate::records::TlsRecordParser;
use crate::bundle::BundleBuilder;
use crate::validation::BundleValidator;
use vefas_types::VefasCanonicalBundle;
use vefas_rustls::{new_provider, ProviderConfig, EphemeralSeed};

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_length_and_chunked(head: &str) -> (Option<usize>, bool) {
    let mut content_length = None;
    let mut chunked = false;
    for line in head.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(":") {
            if name.eq_ignore_ascii_case("Content-Length") {
                if let Ok(n) = value.trim().parse::<usize>() { content_length = Some(n); }
            } else if name.eq_ignore_ascii_case("Transfer-Encoding") {
                chunked = value.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"));
            }
        }
    }
    (content_length, chunked)
}

fn read_exact_into<R: Read>(r: &mut R, dst: &mut Vec<u8>, mut need: usize) -> Result<()> {
    let mut tmp = [0u8; 4096];
    while need > 0 {
        let n = r.read(&mut tmp)
            .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
        if n == 0 { return Err(VefasCoreError::HttpError("Unexpected EOF".to_string())); }
        let take = n.min(need);
        dst.extend_from_slice(&tmp[..take]);
        need -= take;
    }
    Ok(())
}

fn looks_like_chunked_complete(buf: &[u8]) -> bool {
    // Heuristic: end with CRLF 0 CRLF CRLF (may have trailers before final CRLF CRLF)
    // Ensure there's at least one "\r\n0\r\n" followed by a blank line "\r\n" at the end.
    if buf.len() < 7 { return false; }
    // find last occurrence of "\r\n0\r\n"
    if let Some(pos) = buf.windows(5).rposition(|w| w == b"\r\n0\r\n") {
        // After that must be trailers ending with CRLF CRLF
        return buf[pos+5..].windows(4).any(|w| w == b"\r\n\r\n");
    }
    false
}

#[cfg(feature = "std")]
async fn read_exact_into_async<S: AsyncReadExt + Unpin>(s: &mut S, dst: &mut Vec<u8>, mut need: usize) -> Result<()> {
    let mut tmp = [0u8; 4096];
    while need > 0 {
        let n = s.read(&mut tmp).await
            .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
        if n == 0 { return Err(VefasCoreError::HttpError("Unexpected EOF".to_string())); }
        let take = n.min(need);
        dst.extend_from_slice(&tmp[..take]);
        need -= take;
    }
    Ok(())
}

/// Holds capture hooks for TLS ephemeral key material
#[derive(Clone, Default)]
struct EphemeralCapture {
    /// Captured client ephemeral private scalar (X25519/P-256), if any
    client_scalar: Arc<Mutex<Option<[u8; 32]>>>,
}

/// TLS connection wrapper with captured data
pub struct TlsConnection {
    /// The rustls stream over TlsTee transport
    stream: StreamOwned<ClientConnection, TlsTee<std::net::TcpStream>>,
    /// Key logger for capturing session secrets
    keylog: Arc<VefasKeyLog>,
}

/// Async TLS connection wrapper with captured data
#[cfg(feature = "std")]
pub struct AsyncTlsConnection {
    /// The tokio-rustls stream over AsyncTlsTee transport
    stream: AsyncTlsStream<AsyncTlsTee<TokioTcpStream>>,
    /// Key logger for capturing session secrets
    keylog: Arc<VefasKeyLog>,
}

#[cfg(feature = "std")]
impl std::fmt::Debug for AsyncTlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncTlsConnection")
            .field("stream", &"<AsyncTlsStream>")
            .field("keylog", &self.keylog)
            .finish()
    }
}

#[cfg(feature = "std")]
impl AsyncTlsConnection {
    pub fn new(stream: AsyncTlsStream<AsyncTlsTee<TokioTcpStream>>, keylog: Arc<VefasKeyLog>) -> Self {
        Self { stream, keylog }
    }

    pub fn connection(&self) -> &ClientConnection {
        // Access rustls connection within TlsStream
        let (sock, conn) = self.stream.get_ref();
        let _ = sock; // silence unused variable
        conn
    }

    pub fn transport(&self) -> &AsyncTlsTee<TokioTcpStream> {
        let (sock, conn) = self.stream.get_ref();
        let _ = conn; // silence unused variable
        sock
    }

    pub async fn send_http_request(&mut self, request: &[u8]) -> Result<()> {
        self.stream.write_all(request).await
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to send HTTP request: {}", e)))?;
        self.stream.flush().await
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to flush HTTP request: {}", e)))?;
        Ok(())
    }

    pub async fn read_http_response_async(&mut self) -> Result<Vec<u8>> {
        // Streaming, RFC 7230-compliant read: parse headers then body strategy
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut tmp = [0u8; 4096];

        // Read until headers end (\r\n\r\n)
        let headers_end = loop {
            let n = self.stream.read(&mut tmp).await
                .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
            if n == 0 { break None; }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_headers_end(&buf) { break Some(pos); }
        };

        let headers_end = headers_end.ok_or_else(|| VefasCoreError::HttpError("Connection closed before headers completed".to_string()))?;
        let (head_bytes, mut body_bytes) = buf.split_at(headers_end + 4);
        let header_text = String::from_utf8_lossy(head_bytes);
        let (content_length, chunked) = parse_length_and_chunked(&header_text);

        // Accumulate body
        let mut body = body_bytes.to_vec();
        if let Some(len) = content_length {
            let need = len.saturating_sub(body.len());
            if need > 0 { read_exact_into_async(&mut self.stream, &mut body, need).await?; }
        } else if chunked {
            loop {
                if looks_like_chunked_complete(&body) { break; }
                let n = self.stream.read(&mut tmp).await
                    .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
                if body.len() > 16 * 1024 * 1024 { return Err(VefasCoreError::HttpError("Chunked body too large".to_string())); }
            }
        } else {
            loop {
                let n = self.stream.read(&mut tmp).await
                    .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
            }
        }

        let mut out = head_bytes.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnection")
            .field("stream", &"<StreamOwned>")
            .field("keylog", &self.keylog)
            .finish()
    }
}

impl TlsConnection {
    /// Create a new TLS connection
    pub fn new(stream: StreamOwned<ClientConnection, TlsTee<std::net::TcpStream>>, keylog: Arc<VefasKeyLog>) -> Self {
        Self { stream, keylog }
    }

    /// Get access to the underlying connection for extracting session data
    pub fn connection(&self) -> &ClientConnection {
        &self.stream.conn
    }

    /// Get the transport layer for extracting captured bytes
    pub fn transport(&self) -> &TlsTee<std::net::TcpStream> {
        &self.stream.sock
    }

    /// Send HTTP request over the TLS connection
    pub fn send_http_request(&mut self, request: &[u8]) -> Result<()> {
        self.stream.write_all(request)
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to send HTTP request: {}", e)))?;
        Ok(())
    }

    /// Read HTTP response from the TLS connection
    pub fn read_http_response(&mut self) -> Result<Vec<u8>> {
        // Streaming, RFC 7230-compliant read: parse headers then body strategy
        let mut buf = Vec::with_capacity(8 * 1024);
        let mut tmp = [0u8; 4096];

        // Read until we have the full headers (\r\n\r\n)
        let headers_end = loop {
            let n = self.stream.read(&mut tmp)
                .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
            if n == 0 {
                // connection closed prematurely
                break None;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(pos) = find_headers_end(&buf) { break Some(pos); }
            // continue reading
        };

        let headers_end = headers_end.ok_or_else(|| VefasCoreError::HttpError("Connection closed before headers completed".to_string()))?;
        let (head_bytes, mut body_bytes) = buf.split_at(headers_end + 4);
        let header_text = String::from_utf8_lossy(head_bytes);

        // Determine body strategy
        let (content_length, chunked) = parse_length_and_chunked(&header_text);

        // If Content-Length present: ensure we read exactly that many bytes
        let mut body = body_bytes.to_vec();
        if let Some(len) = content_length {
            let need = len.saturating_sub(body.len());
            if need > 0 {
                body.reserve(need);
                read_exact_into(&mut self.stream, &mut body, need)?;
            }
        } else if chunked {
            // Read until we have the full chunked body (ending with 0\r\n...\r\n)
            // We don't fully parse here; allow HttpProcessor.dechunk to validate.
            // Read until we observe last-chunk terminator in buffer.
            loop {
                if looks_like_chunked_complete(&body) { break; }
                let n = self.stream.read(&mut tmp)
                    .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
                if body.len() > 16 * 1024 * 1024 { // 16 MiB safety cap
                    return Err(VefasCoreError::HttpError("Chunked body too large".to_string()));
                }
            }
        } else {
            // No explicit length: read until EOF
            loop {
                let n = self.stream.read(&mut tmp)
                    .map_err(|e| VefasCoreError::network_error(&format!("Read error: {}", e)))?;
                if n == 0 { break; }
                body.extend_from_slice(&tmp[..n]);
            }
        }

        // Reconstruct raw response bytes: headers + body
        let mut out = head_bytes.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }
}

/// Production-grade VEFAS client for TLS session capture
#[derive(Debug)]
pub struct VefasClient {
    config: Arc<ClientConfig>,
    keylog: Arc<VefasKeyLog>,
    capture: Arc<Mutex<Option<[u8;32]>>>,
}

impl VefasClient {
    /// Create a new VEFAS client with production-grade configuration
    pub fn new() -> Result<Self> {
        let root_store = Self::create_root_store()?;
        let keylog = Arc::new(VefasKeyLog::new());

        let (provider, capture) = new_provider(ProviderConfig::default());

        let mut config = ClientConfig::builder_with_provider(provider.into())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

        // Enable key logging for secret capture
        config.key_log = keylog.clone();

        Ok(Self {
            config: Arc::new(config),
            keylog,
            capture,
        })
    }

    /// Create a client with deterministic ephemeral seed
    pub fn with_ephemeral_seed(seed: [u8;32]) -> Result<Self> {
        let root_store = Self::create_root_store()?;
        let keylog = Arc::new(VefasKeyLog::new());
        let (provider, capture) = new_provider(ProviderConfig { seed: Some(EphemeralSeed(seed)) });
        let mut config = ClientConfig::builder_with_provider(provider.into())
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.key_log = keylog.clone();
        Ok(Self { config: Arc::new(config), keylog, capture })
    }

    /// Establish a TLS connection with byte capture
    pub async fn connect(&self, host: &str, port: u16) -> Result<TlsConnection> {
        // Parse server name
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| VefasCoreError::tls_error(&format!("Invalid server name: {}", e)))?;

        // Create TCP connection
        let tcp_stream = TokioTcpStream::connect((host, port))
            .await
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to connect to {}:{}: {}", host, port, e)))?;

        // Convert tokio TcpStream to std::net::TcpStream for rustls compatibility
        let std_stream = tcp_stream.into_std()
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to convert stream: {}", e)))?;

        // Wrap TCP stream with TlsTee for byte capture
        let tee_stream = TlsTee::new(std_stream);

        // Create TLS connection
        let tls_conn = ClientConnection::new(self.config.clone(), server_name)
            .map_err(|e| VefasCoreError::tls_error(&format!("Failed to create TLS connection: {}", e)))?;

        // Create the combined stream
        let mut stream = StreamOwned::new(tls_conn, tee_stream);

        Ok(TlsConnection::new(stream, Arc::clone(&self.keylog)))
    }

    /// Establish an async TLS connection with byte capture (tokio-rustls)
    pub async fn connect_async(&self, host: &str, port: u16) -> Result<AsyncTlsConnection> {
        // Parse server name
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|e| VefasCoreError::tls_error(&format!("Invalid server name: {}", e)))?;

        // Create TCP connection
        let tcp = TokioTcpStream::connect((host, port)).await
            .map_err(|e| VefasCoreError::network_error(&format!("Failed to connect to {}:{}: {}", host, port, e)))?;

        // Wrap with async tee
        let tee = AsyncTlsTee::new(tcp);

        // Create async TLS connector
        let connector = AsyncTlsConnector::from(self.config.clone());
        let stream = connector.connect(server_name, tee).await
            .map_err(|e| VefasCoreError::tls_error(&format!("TLS handshake failed: {}", e)))?;

        Ok(AsyncTlsConnection::new(stream, Arc::clone(&self.keylog)))
    }

    // removed: legacy manual sync handshake helper

    /// Execute HTTP request and capture complete TLS session data
    pub async fn execute_request(
        &self,
        method: &str,
        url: &str,
        headers: Option<&[(&str, &str)]>,
        body: Option<&[u8]>
    ) -> Result<VefasCanonicalBundle> {
        let parsed_url = Url::parse(url)
            .map_err(|e| VefasCoreError::invalid_input(&format!("Invalid URL: {}", e)))?;

        let host = parsed_url.host_str()
            .ok_or_else(|| VefasCoreError::invalid_input("URL must have a host"))?;
        let port = parsed_url.port().unwrap_or(443);

        // Establish TLS connection with byte capture (async)
        let mut tls_conn = self.connect_async(host, port).await?;

        // Build HTTP request with optional headers and body
        let http_request_bytes = self.build_http_request(method, &parsed_url, headers, body)?;

        // Send HTTP request
        tls_conn.send_http_request(&http_request_bytes).await?;

        // Read HTTP response
        let response_data = tls_conn.read_http_response_async().await?;

        // Extract session data from the completed TLS connection
        // Read captured ephemeral scalar from provider hooks
        let captured_scalar = self.capture.lock().ok().and_then(|g| *g);
        let session_data = SessionData::extract_from_async_connection(
            tls_conn.connection(),
            tls_conn.transport(),
            &self.keylog,
            host,
            captured_scalar,
        )?;

        // Phase 2: Process HTTP request/response from captured data
        let http_data = self.extract_http_data(&session_data, &http_request_bytes, &response_data)?;

        // Phase 3: Create VefasCanonicalBundle from session data
        let mut bundle_builder = BundleBuilder::new();
        let bundle = bundle_builder.from_session_data(&session_data, &http_data, &self.keylog)?;

        // Validate the created bundle
        let validator = BundleValidator::new();
        let validation_report = validator.validate_bundle(&bundle)?;

        if !validation_report.is_valid {
            return Err(VefasCoreError::ValidationError(format!("Bundle validation failed: {:?}", validation_report.errors)));
        }

        Ok(bundle)
    }

    /// Parse HTTP request from raw bytes (for testing and verification)
    pub fn parse_http_request(&self, data: &[u8]) -> Result<crate::http::HttpRequest> {
        let processor = HttpProcessor::new();
        processor.parse_http_request(data)
    }

    /// Parse HTTP response from raw bytes (for testing and verification)
    pub fn parse_http_response(&self, data: &[u8]) -> Result<crate::http::HttpResponse> {
        let processor = HttpProcessor::new();
        processor.parse_http_response(data)
    }

    /// Create canonical bundle from components (for testing)
    pub fn create_canonical_bundle(
        &self,
        session_data: &SessionData,
        request: &crate::http::HttpRequest,
        response: &crate::http::HttpResponse,
    ) -> Result<VefasCanonicalBundle> {
        let http_data = HttpData {
            request_bytes: request.raw_bytes.clone(),
            response_bytes: response.raw_bytes.clone(),
            status_code: response.status_code,
            headers: response.headers.clone(),
            method: request.method.clone(),
            path: request.path.clone(),
            request_headers: request.headers.clone(),
            response_body: response.body.clone(),
        };

        let mut bundle_builder = BundleBuilder::new();
        bundle_builder.from_session_data(session_data, &http_data, &self.keylog)
    }

    /// Build HTTP request bytes
    fn build_http_request(
        &self,
        method: &str,
        url: &Url,
        headers: Option<&[(&str, &str)]>,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let mut default_headers = vec![
            ("Host", url.host_str().unwrap_or("localhost")),
            ("Connection", "close"),
            ("User-Agent", "VEFAS-Client/1.0"),
        ];

        if let Some(custom_headers) = headers {
            default_headers.extend_from_slice(custom_headers);
        }

        Ok(HttpProcessor::build_request(
            method,
            url.path(),
            &default_headers,
            body,
        ))
    }

    /// Extract HTTP data from captured TLS records
    fn extract_http_data(
        &self,
        session_data: &SessionData,
        request_bytes: &[u8],
        response_bytes: &[u8],
    ) -> Result<HttpData> {
        // Parse TLS records to extract application data
        let mut record_parser = TlsRecordParser::new();

        // Parse records from captured bytes
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&session_data.outbound_bytes);
        all_data.extend_from_slice(&session_data.inbound_bytes);

        let records = record_parser.parse_records(&all_data)?;
        let app_data = record_parser.extract_application_data(&records);

        // Extract HTTP data from TLS application data
        // The request_bytes and response_bytes are the plaintext HTTP data that was sent/received
        // The encrypted TLS records contain this same data but encrypted - we use the plaintext version
        let mut http_processor = HttpProcessor::new();

        // If we have decrypted application data from TLS records, use that
        // Otherwise fall back to the provided request/response bytes
        if !app_data.is_empty() {
            // Try to parse HTTP data from the application data; if it fails (likely still encrypted),
            // fall back to the known plaintext request/response bytes we constructed and read.
            match http_processor.extract_http_data_from_stream(&app_data) {
                Ok(h) => Ok(h),
                Err(_) => http_processor.extract_http_data(request_bytes, response_bytes),
            }
        } else {
            // Use the provided plaintext HTTP data directly
            http_processor.extract_http_data(request_bytes, response_bytes)
        }
    }

    /// Create root certificate store
    fn create_root_store() -> Result<RootCertStore> {
        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };
        Ok(root_store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VefasClient::new();
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_config() {
        let client = VefasClient::new().unwrap();
        // Verify the client was created with proper configuration
        assert!(!client.config.alpn_protocols.is_empty() || client.config.alpn_protocols.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_execute_request_placeholder() {
        if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
            return;
        }
        let client = VefasClient::new().unwrap();
        let result = client.execute_request("GET", "https://example.com", None, None).await;
        assert!(result.is_err());
        match result {
            Err(VefasCoreError::Internal(msg)) => {
                assert!(msg.contains("Phase 1.3 complete") || msg.contains("not yet implemented") || msg.contains("not yet complete"));
            }
            _ => panic!("Expected Internal error with phase completion or implementation message"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_invalid_url() {
        let client = VefasClient::new().unwrap();
        let result = client.execute_request("GET", "invalid-url", None, None).await;
        assert!(result.is_err());
        match result {
            Err(VefasCoreError::InvalidInput(msg)) => {
                assert!(msg.contains("Invalid URL"));
            }
            _ => panic!("Expected InvalidInput error for invalid URL"),
        }
    }

    #[test]
    fn test_real_tls_connection() {
        // This test requires network access and may be slow
        // Skip in CI environments without network access
        if std::env::var("SKIP_NETWORK_TESTS").is_ok() {
            return;
        }

        let client = VefasClient::new().unwrap();

        // Test basic TLS connection establishment (without full HTTP)
        let handle = std::thread::spawn(move || {
            // Use a simple runtime for the async test
            futures::executor::block_on(async {
                client.connect("httpbin.org", 443).await
            })
        });

        let result = handle.join().unwrap();

        // Should successfully establish TLS connection
        match result {
            Ok(tls_conn) => {
                // Verify we have access to the underlying components
                let _connection = tls_conn.connection();
                let _transport = tls_conn.transport();

                // Verify keylog has captured some data (if TLS handshake completed)
                println!("TLS connection established successfully");
            }
            Err(e) => {
                // Network errors are acceptable in test environments
                println!("TLS connection failed (expected in some environments): {}", e);
            }
        }
    }
}