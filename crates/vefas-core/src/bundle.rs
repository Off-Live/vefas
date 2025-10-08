//! # VefasCanonicalBundle Creation
//!
//! This module provides production-grade bundle creation for transforming
//! captured TLS session data into the canonical format required for guest verification.
//! It ensures deterministic serialization and complete capture of all necessary data.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::{
    Result, VefasCoreError,
};
use vefas_rustls::transcript_bundle::TranscriptBundle;
use vefas_types::VefasCanonicalBundle;

/// Clean architecture that eliminates complex TLS parsing
/// and works directly with raw captured bytes from rustls.
#[derive(Debug)]
pub struct BundleBuilder;

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleBuilder {
    /// Create a new bundle builder
    pub fn new() -> Self {
        Self
    }

    /// Create a canonical bundle from a TranscriptBundle
    /// 
    /// This is the primary method in the new architecture. It converts
    /// raw captured TLS data into the canonical format for guest verification.
    pub fn from_transcript_bundle(
        &self,
        transcript_bundle: &TranscriptBundle,
        domain: String,
        timestamp: u64,
        expected_status: u16,
        verifier_nonce: [u8; 32],
    ) -> Result<VefasCanonicalBundle> {
        // Convert TranscriptBundle to VefasCanonicalBundle using the new conversion method
        transcript_bundle
            .to_vefas_canonical_bundle(domain, timestamp, expected_status, verifier_nonce)
            .map_err(|e| VefasCoreError::tls_error(&format!("Failed to convert transcript bundle: {:?}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vefas_rustls::transcript_bundle::{TranscriptBundle, RawHandshakeMessage};

    #[test]
    fn test_bundle_builder_from_transcript_bundle() {
        let mut transcript_bundle = TranscriptBundle::new();
        transcript_bundle.timestamp = 1640995200;
        transcript_bundle.cipher_suite = 0x1301; // TLS_AES_128_GCM_SHA256
        
        // Add a ClientHello message
        transcript_bundle.handshake_messages.push(RawHandshakeMessage {
            message_type: 1, // ClientHello
            raw_bytes: vec![0x01, 0x00, 0x00, 0x10, 0x03, 0x03], // Mock ClientHello
        });
        
        // Add a ServerHello message
        transcript_bundle.handshake_messages.push(RawHandshakeMessage {
            message_type: 2, // ServerHello
            raw_bytes: vec![0x02, 0x00, 0x00, 0x10, 0x03, 0x04], // Mock ServerHello
        });
        
        transcript_bundle.server_finished = vec![0x14, 0x00, 0x00, 0x20]; // Mock Finished
        transcript_bundle.shared_secret = vec![0x01; 32]; // Mock shared secret
        transcript_bundle.http_request_canonical = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec();
        transcript_bundle.http_response_canonical = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec();
        
        let builder = BundleBuilder::new();
        let result = builder.from_transcript_bundle(
            &transcript_bundle,
            "example.com".to_string(),
            1640995200,
            200,
            [0x42; 32],
        );
        
        assert!(result.is_ok());
        let bundle = result.unwrap();
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.expected_status, 200);
    }
}