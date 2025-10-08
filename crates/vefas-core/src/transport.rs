//! TLS transport wrapper for byte-perfect capture
//!
//! This module implements the TlsTee transport wrapper that captures exact bytes
//! sent and received on the wire during TLS connections. This is the foundation
//! for the revolutionary host-rustls + guest-verifier architecture.
//!
//! ## Design Principles
//!
//! - **Byte-perfect capture**: Every byte sent/received is logged
//! - **Thread-safe**: Arc<Mutex<>> for concurrent access to logs
//! - **Zero-copy where possible**: Minimal performance overhead
//! - **Production-ready**: Comprehensive error handling and validation

use crate::error::{Result, VefasCoreError};
use std::io::{Error as IoError, ErrorKind, Read, Write};
use std::sync::{Arc, Mutex};

#[cfg(feature = "std")]
use std::pin::Pin;
#[cfg(feature = "std")]
use std::task::{Context, Poll};
#[cfg(feature = "std")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Transport wrapper that captures all bytes sent and received
///
/// TlsTee implements a "tee" pattern, logging all data while transparently
/// passing it through to the underlying transport. This enables complete
/// TLS session reconstruction for zkTLS verification.
#[derive(Debug)]
pub struct TlsTee<T: Read + Write> {
    /// Underlying transport (typically TcpStream)
    inner: T,
    /// Bytes sent from client to server (outbound)
    outbound_log: Arc<Mutex<Vec<u8>>>,
    /// Bytes received from server to client (inbound)
    inbound_log: Arc<Mutex<Vec<u8>>>,
    /// Maximum number of bytes to retain per direction (ring buffer cap)
    max_log_bytes: usize,
    /// Number of bytes discarded due to caps
    dropped_outbound: Arc<Mutex<usize>>,
    /// Number of bytes discarded due to caps
    dropped_inbound: Arc<Mutex<usize>>,
}

impl<T: Read + Write> TlsTee<T> {
    /// Create a new TlsTee wrapper around a transport
    pub fn new(transport: T) -> Self {
        // Default caps: 2 MiB per direction
        Self::with_caps(transport, 2 * 1024 * 1024)
    }

    /// Create with explicit per-direction cap (in bytes)
    pub fn with_caps(transport: T, per_direction_cap: usize) -> Self {
        Self {
            inner: transport,
            outbound_log: Arc::new(Mutex::new(Vec::new())),
            inbound_log: Arc::new(Mutex::new(Vec::new())),
            max_log_bytes: per_direction_cap,
            dropped_outbound: Arc::new(Mutex::new(0)),
            dropped_inbound: Arc::new(Mutex::new(0)),
        }
    }

    /// Get a copy of all outbound bytes (client → server)
    pub fn outbound_bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .outbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock outbound log: {}", e)))?
            .clone())
    }

    /// Get a copy of all inbound bytes (server → client)
    pub fn inbound_bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .inbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock inbound log: {}", e)))?
            .clone())
    }

    /// Get the total number of outbound bytes captured
    pub fn outbound_len(&self) -> Result<usize> {
        Ok(self
            .outbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock outbound log: {}", e)))?
            .len())
    }

    /// Get the total number of inbound bytes captured
    pub fn inbound_len(&self) -> Result<usize> {
        Ok(self
            .inbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock inbound log: {}", e)))?
            .len())
    }

    /// Get number of outbound bytes dropped due to cap
    pub fn dropped_outbound(&self) -> Result<usize> {
        Ok(*self.dropped_outbound.lock().map_err(|e| {
            VefasCoreError::internal(&format!("Failed to lock dropped_outbound: {}", e))
        })?)
    }

    /// Get number of inbound bytes dropped due to cap
    pub fn dropped_inbound(&self) -> Result<usize> {
        Ok(*self.dropped_inbound.lock().map_err(|e| {
            VefasCoreError::internal(&format!("Failed to lock dropped_inbound: {}", e))
        })?)
    }

    /// Clear captured bytes (useful for memory management)
    pub fn clear_logs(&self) -> Result<()> {
        {
            let mut outbound = self.outbound_log.lock().map_err(|e| {
                VefasCoreError::internal(&format!("Failed to lock outbound log: {}", e))
            })?;
            outbound.clear();
        }
        {
            let mut inbound = self.inbound_log.lock().map_err(|e| {
                VefasCoreError::internal(&format!("Failed to lock inbound log: {}", e))
            })?;
            inbound.clear();
        }
        {
            let mut d = self.dropped_outbound.lock().map_err(|e| {
                VefasCoreError::internal(&format!("Failed to lock dropped_outbound: {}", e))
            })?;
            *d = 0;
        }
        {
            let mut d = self.dropped_inbound.lock().map_err(|e| {
                VefasCoreError::internal(&format!("Failed to lock dropped_inbound: {}", e))
            })?;
            *d = 0;
        }
        Ok(())
    }

    /// Get references to the log containers for shared access
    pub fn log_handles(&self) -> (Arc<Mutex<Vec<u8>>>, Arc<Mutex<Vec<u8>>>) {
        (self.outbound_log.clone(), self.inbound_log.clone())
    }

    /// Consume the TlsTee and return the inner transport plus captured bytes
    pub fn into_parts(self) -> Result<(T, Vec<u8>, Vec<u8>)> {
        let outbound = self
            .outbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock outbound log: {}", e)))?
            .clone();

        let inbound = self
            .inbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock inbound log: {}", e)))?
            .clone();

        Ok((self.inner, outbound, inbound))
    }
}

impl<T: Read + Write> Read for TlsTee<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Read from underlying transport
        let bytes_read = self.inner.read(buf)?;

        if bytes_read > 0 {
            // Log the inbound data
            let data_to_log = &buf[..bytes_read];
            if let Ok(mut inbound_log) = self.inbound_log.lock() {
                // Enforce cap as ring buffer
                if inbound_log.len() + data_to_log.len() > self.max_log_bytes {
                    let overflow = inbound_log.len() + data_to_log.len() - self.max_log_bytes;
                    let drop = overflow.min(inbound_log.len());
                    if drop > 0 {
                        inbound_log.drain(0..drop);
                        if let Ok(mut dropped) = self.dropped_inbound.lock() {
                            *dropped += drop;
                        }
                    }
                }
                inbound_log.extend_from_slice(data_to_log);
            } else {
                return Err(IoError::new(
                    ErrorKind::Other,
                    "Failed to acquire inbound log lock",
                ));
            }
        }

        Ok(bytes_read)
    }
}

impl<T: Read + Write> Write for TlsTee<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Write to underlying transport
        let bytes_written = self.inner.write(buf)?;

        if bytes_written > 0 {
            // Log the outbound data
            let data_to_log = &buf[..bytes_written];
            if let Ok(mut outbound_log) = self.outbound_log.lock() {
                if outbound_log.len() + data_to_log.len() > self.max_log_bytes {
                    let overflow = outbound_log.len() + data_to_log.len() - self.max_log_bytes;
                    let drop = overflow.min(outbound_log.len());
                    if drop > 0 {
                        outbound_log.drain(0..drop);
                        if let Ok(mut dropped) = self.dropped_outbound.lock() {
                            *dropped += drop;
                        }
                    }
                }
                outbound_log.extend_from_slice(data_to_log);
            } else {
                return Err(IoError::new(
                    ErrorKind::Other,
                    "Failed to acquire outbound log lock",
                ));
            }
        }

        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Async transport tee that captures all bytes with backpressure-friendly I/O
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct AsyncTlsTee<T: AsyncRead + AsyncWrite + Unpin> {
    inner: T,
    outbound_log: Arc<Mutex<Vec<u8>>>,
    inbound_log: Arc<Mutex<Vec<u8>>>,
    max_log_bytes: usize,
    dropped_outbound: Arc<Mutex<usize>>,
    dropped_inbound: Arc<Mutex<usize>>,
}

#[cfg(feature = "std")]
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncTlsTee<T> {
    pub fn new(transport: T) -> Self {
        Self::with_caps(transport, 2 * 1024 * 1024)
    }

    pub fn with_caps(transport: T, per_direction_cap: usize) -> Self {
        Self {
            inner: transport,
            outbound_log: Arc::new(Mutex::new(Vec::new())),
            inbound_log: Arc::new(Mutex::new(Vec::new())),
            max_log_bytes: per_direction_cap,
            dropped_outbound: Arc::new(Mutex::new(0)),
            dropped_inbound: Arc::new(Mutex::new(0)),
        }
    }

    pub fn outbound_bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .outbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock outbound log: {}", e)))?
            .clone())
    }

    pub fn inbound_bytes(&self) -> Result<Vec<u8>> {
        Ok(self
            .inbound_log
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock inbound log: {}", e)))?
            .clone())
    }

    fn enforce_cap(
        log: &mut Vec<u8>,
        cap: usize,
        drop_counter: &Arc<Mutex<usize>>,
        incoming_len: usize,
    ) {
        let needed = log.len().saturating_add(incoming_len);
        if needed > cap {
            let overflow = needed - cap;
            let drop = overflow.min(log.len());
            if drop > 0 {
                log.drain(0..drop);
                if let Ok(mut d) = drop_counter.lock() {
                    *d += drop;
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for AsyncTlsTee<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        let mut tmp = ReadBuf::new(buf.initialize_unfilled());
        match Pin::new(&mut me.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(())) => {
                let filled = tmp.filled().len();
                if filled > 0 {
                    if let Ok(mut inbound) = me.inbound_log.lock() {
                        AsyncTlsTee::<T>::enforce_cap(
                            &mut inbound,
                            me.max_log_bytes,
                            &me.dropped_inbound,
                            filled,
                        );
                        inbound.extend_from_slice(&tmp.filled());
                    } else {
                        return Poll::Ready(Err(IoError::new(
                            ErrorKind::Other,
                            "Failed to acquire inbound log lock",
                        )));
                    }
                    buf.advance(filled);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(feature = "std")]
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for AsyncTlsTee<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        match Pin::new(&mut me.inner).poll_write(cx, data) {
            Poll::Ready(Ok(n)) => {
                if n > 0 {
                    if let Ok(mut outbound) = me.outbound_log.lock() {
                        AsyncTlsTee::<T>::enforce_cap(
                            &mut outbound,
                            me.max_log_bytes,
                            &me.dropped_outbound,
                            n,
                        );
                        outbound.extend_from_slice(&data[..n]);
                    } else {
                        return Poll::Ready(Err(IoError::new(
                            ErrorKind::Other,
                            "Failed to acquire outbound log lock",
                        )));
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Mock transport for testing TlsTee behavior
#[cfg(test)]
pub struct MockTransport {
    read_data: Vec<u8>,
    read_pos: usize,
    written_data: Vec<u8>,
    should_fail_read: bool,
    should_fail_write: bool,
}

#[cfg(test)]
impl MockTransport {
    pub fn new(read_data: Vec<u8>) -> Self {
        Self {
            read_data,
            read_pos: 0,
            written_data: Vec::new(),
            should_fail_read: false,
            should_fail_write: false,
        }
    }

    pub fn with_write_failure(mut self) -> Self {
        self.should_fail_write = true;
        self
    }

    pub fn with_read_failure(mut self) -> Self {
        self.should_fail_read = true;
        self
    }

    pub fn written_data(&self) -> &[u8] {
        &self.written_data
    }
}

#[cfg(test)]
impl Read for MockTransport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.should_fail_read {
            return Err(IoError::new(ErrorKind::BrokenPipe, "Mock read failure"));
        }

        let available = self.read_data.len() - self.read_pos;
        if available == 0 {
            return Ok(0);
        }

        let to_copy = core::cmp::min(buf.len(), available);
        buf[..to_copy].copy_from_slice(&self.read_data[self.read_pos..self.read_pos + to_copy]);
        self.read_pos += to_copy;
        Ok(to_copy)
    }
}

#[cfg(test)]
impl Write for MockTransport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.should_fail_write {
            return Err(IoError::new(ErrorKind::BrokenPipe, "Mock write failure"));
        }

        self.written_data.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn test_tls_tee_creation() {
        let mock_transport = MockTransport::new(vec![]);
        let tee = TlsTee::new(mock_transport);

        // Initially, logs should be empty
        assert_eq!(tee.outbound_len().unwrap(), 0);
        assert_eq!(tee.inbound_len().unwrap(), 0);
    }

    #[test]
    fn test_write_logging() {
        let mock_transport = MockTransport::new(vec![]);
        let mut tee = TlsTee::new(mock_transport);

        let test_data = b"Hello, TLS!";
        let bytes_written = tee.write(test_data).unwrap();

        assert_eq!(bytes_written, test_data.len());
        assert_eq!(tee.outbound_len().unwrap(), test_data.len());
        assert_eq!(tee.outbound_bytes().unwrap(), test_data);
        assert_eq!(tee.inbound_len().unwrap(), 0);
    }

    #[test]
    fn test_read_logging() {
        let test_data = b"Hello from server!";
        let mock_transport = MockTransport::new(test_data.to_vec());
        let mut tee = TlsTee::new(mock_transport);

        let mut buf = [0u8; 32];
        let bytes_read = tee.read(&mut buf).unwrap();

        assert_eq!(bytes_read, test_data.len());
        assert_eq!(tee.inbound_len().unwrap(), test_data.len());
        assert_eq!(tee.inbound_bytes().unwrap(), test_data);
        assert_eq!(tee.outbound_len().unwrap(), 0);
        assert_eq!(&buf[..bytes_read], test_data);
    }

    #[test]
    fn test_bidirectional_logging() {
        let server_data = b"HTTP/1.1 200 OK\r\n\r\n";
        let mock_transport = MockTransport::new(server_data.to_vec());
        let mut tee = TlsTee::new(mock_transport);

        // Send client data
        let client_data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        tee.write(client_data).unwrap();

        // Read server response
        let mut buf = [0u8; 64];
        let bytes_read = tee.read(&mut buf).unwrap();

        // Verify both directions are logged
        assert_eq!(tee.outbound_bytes().unwrap(), client_data);
        assert_eq!(tee.inbound_bytes().unwrap(), server_data);
        assert_eq!(bytes_read, server_data.len());
        assert_eq!(&buf[..bytes_read], server_data);
    }

    #[test]
    fn test_multiple_write_operations() {
        let mock_transport = MockTransport::new(vec![]);
        let mut tee = TlsTee::new(mock_transport);

        let data1 = b"First chunk";
        let data2 = b"Second chunk";
        let data3 = b"Third chunk";

        tee.write(data1).unwrap();
        tee.write(data2).unwrap();
        tee.write(data3).unwrap();

        let logged_data = tee.outbound_bytes().unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(data1);
        expected.extend_from_slice(data2);
        expected.extend_from_slice(data3);
        assert_eq!(logged_data, expected);
    }

    #[test]
    fn test_multiple_read_operations() {
        let test_data = b"This is a longer response from the server that will be read in chunks";
        let mock_transport = MockTransport::new(test_data.to_vec());
        let mut tee = TlsTee::new(mock_transport);

        let mut total_read = Vec::new();
        let mut buf = [0u8; 16]; // Small buffer to force multiple reads

        loop {
            let bytes_read = tee.read(&mut buf).unwrap();
            if bytes_read == 0 {
                break;
            }
            total_read.extend_from_slice(&buf[..bytes_read]);
        }

        assert_eq!(total_read, test_data);
        assert_eq!(tee.inbound_bytes().unwrap(), test_data);
    }

    #[test]
    fn test_write_error_propagation() {
        let mock_transport = MockTransport::new(vec![]).with_write_failure();
        let mut tee = TlsTee::new(mock_transport);

        let result = tee.write(b"test data");
        assert!(result.is_err());

        // Log should be empty since write failed
        assert_eq!(tee.outbound_len().unwrap(), 0);
    }

    #[test]
    fn test_read_error_propagation() {
        let mock_transport = MockTransport::new(vec![]).with_read_failure();
        let mut tee = TlsTee::new(mock_transport);

        let mut buf = [0u8; 10];
        let result = tee.read(&mut buf);
        assert!(result.is_err());

        // Log should be empty since read failed
        assert_eq!(tee.inbound_len().unwrap(), 0);
    }

    #[test]
    fn test_clear_logs() {
        let test_data = b"test data";
        let mock_transport = MockTransport::new(test_data.to_vec());
        let mut tee = TlsTee::new(mock_transport);

        // Generate some logged data
        tee.write(b"outbound").unwrap();
        let mut buf = [0u8; 16];
        tee.read(&mut buf).unwrap();

        // Verify data is logged
        assert!(tee.outbound_len().unwrap() > 0);
        assert!(tee.inbound_len().unwrap() > 0);

        // Clear logs
        tee.clear_logs().unwrap();

        // Verify logs are empty
        assert_eq!(tee.outbound_len().unwrap(), 0);
        assert_eq!(tee.inbound_len().unwrap(), 0);
    }

    #[test]
    fn test_into_parts() {
        let server_data = b"server response";
        let mock_transport = MockTransport::new(server_data.to_vec());
        let mut tee = TlsTee::new(mock_transport);

        // Generate logged data
        let client_data = b"client request";
        tee.write(client_data).unwrap();
        let mut buf = [0u8; 32];
        tee.read(&mut buf).unwrap();

        // Extract parts
        let (transport, outbound, inbound) = tee.into_parts().unwrap();

        assert_eq!(outbound, client_data);
        assert_eq!(inbound, server_data);
        assert_eq!(transport.written_data(), client_data);
    }

    #[test]
    fn test_log_handles_shared_access() {
        let mock_transport = MockTransport::new(vec![]);
        let mut tee = TlsTee::new(mock_transport);

        let (outbound_handle, _inbound_handle) = tee.log_handles();

        // Write through tee
        tee.write(b"test").unwrap();

        // Access through handle
        {
            let outbound_log = outbound_handle.lock().unwrap();
            assert_eq!(*outbound_log, b"test");
        }

        // Verify same data through tee API
        assert_eq!(tee.outbound_bytes().unwrap(), b"test");
    }

    #[test]
    fn test_partial_writes() {
        // Test that partial writes are handled correctly
        let mock_transport = MockTransport::new(vec![]);
        let mut tee = TlsTee::new(mock_transport);

        let data = b"partial write test";
        let bytes_written = tee.write(data).unwrap();

        // MockTransport writes everything, but this tests the logging logic
        assert_eq!(bytes_written, data.len());
        assert_eq!(tee.outbound_bytes().unwrap(), data);
    }

    #[test]
    fn test_zero_byte_operations() {
        let mock_transport = MockTransport::new(vec![]);
        let mut tee = TlsTee::new(mock_transport);

        // Write zero bytes
        let bytes_written = tee.write(&[]).unwrap();
        assert_eq!(bytes_written, 0);
        assert_eq!(tee.outbound_len().unwrap(), 0);

        // Read with empty source
        let mut buf = [0u8; 10];
        let bytes_read = tee.read(&mut buf).unwrap();
        assert_eq!(bytes_read, 0);
        assert_eq!(tee.inbound_len().unwrap(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let mock_transport = MockTransport::new(b"concurrent test".to_vec());
        let tee = Arc::new(Mutex::new(TlsTee::new(mock_transport)));

        let tee_clone = tee.clone();
        let write_handle = thread::spawn(move || {
            let mut tee = tee_clone.lock().unwrap();
            tee.write(b"from thread").unwrap();
        });

        let tee_clone = tee.clone();
        let read_handle = thread::spawn(move || {
            let mut tee = tee_clone.lock().unwrap();
            let mut buf = [0u8; 32];
            tee.read(&mut buf).unwrap()
        });

        write_handle.join().unwrap();
        let bytes_read = read_handle.join().unwrap();

        let tee = tee.lock().unwrap();
        assert_eq!(tee.outbound_bytes().unwrap(), b"from thread");
        assert_eq!(bytes_read, b"concurrent test".len());
    }
}
