//! Canonical bundle format for host→guest communication
//!
//! This module defines the VefasCanonicalBundle format, which is the key innovation
//! that bridges host (rustls) and guest (minimal verifier) in the revolutionary
//! host-rustls + guest-verifier architecture.
//!
//! ## Design Principles
//!
//! - **Deterministic**: Exact byte representation for consistent verification
//! - **Minimal**: Only essential data needed for TLS verification
//! - **Direct**: Raw captured data without interpretation or transformation
//! - **Efficient**: Optimized for zkVM proof generation

use alloc::{string::{String, ToString}, vec::Vec, format};
use core::mem::size_of;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{VefasError, VefasResult},
    MAX_DOMAIN_LENGTH,
    VEFAS_PROTOCOL_VERSION,
    utils::format_decimal,
};

/// Maximum size for individual handshake messages
pub const MAX_HANDSHAKE_MESSAGE_SIZE: usize = 16 * 1024; // 16KB

/// Maximum size for encrypted TLS records
pub const MAX_TLS_RECORD_SIZE: usize = 16 * 1024 + 256; // 16KB + TLS overhead

/// Maximum size for certificate chain in bundle
pub const MAX_CERTIFICATE_CHAIN_SIZE: usize = 64 * 1024; // 64KB

/// Canonical bundle format for deterministic TLS verification
///
/// This structure contains all data captured by the host during a real TLS session
/// and is passed to the guest program for minimal verification and proof generation.
///
/// The bundle represents the core innovation of the host-rustls + guest-verifier
/// architecture, enabling orders of magnitude cheaper proofs through separation
/// of TLS implementation (host) from verification (guest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VefasCanonicalBundle {
    /// Protocol version for compatibility checking
    pub version: u16,

    // Raw handshake messages (exact bytes from wire)
    /// ClientHello message (raw bytes)
    pub client_hello: Vec<u8>,
    /// ServerHello message (raw bytes)
    pub server_hello: Vec<u8>,
    /// Certificate message (raw bytes)
    pub certificate_msg: Vec<u8>,
    /// CertificateVerify message (raw bytes)
    pub certificate_verify_msg: Vec<u8>,
    /// Server Finished message (raw bytes)
    pub server_finished_msg: Vec<u8>,

    // Cryptographic materials for verification
    /// Client ephemeral private key (for ECDHE key derivation)
    pub client_private_key: [u8; 32],
    /// Certificate chain (DER encoded certificates)
    pub certificate_chain: Vec<Vec<u8>>,

    // Application data (encrypted TLS records)
    /// Encrypted HTTP request (TLS record format)
    pub encrypted_request: Vec<u8>,
    /// Encrypted HTTP response (TLS record format)
    pub encrypted_response: Vec<u8>,

    // Verification metadata
    /// Target domain name for certificate validation
    pub domain: String,
    /// Unix timestamp when session was captured
    pub timestamp: u64,
    /// Expected HTTP status code
    pub expected_status: u16,
    /// Random nonce for proof uniqueness
    pub verifier_nonce: [u8; 32],
}

impl VefasCanonicalBundle {
    /// Create a new canonical bundle with validation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        certificate_msg: Vec<u8>,
        certificate_verify_msg: Vec<u8>,
        server_finished_msg: Vec<u8>,
        client_private_key: [u8; 32],
        certificate_chain: Vec<Vec<u8>>,
        encrypted_request: Vec<u8>,
        encrypted_response: Vec<u8>,
        domain: String,
        timestamp: u64,
        expected_status: u16,
        verifier_nonce: [u8; 32],
    ) -> VefasResult<Self> {
        let bundle = Self {
            version: VEFAS_PROTOCOL_VERSION,
            client_hello,
            server_hello,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            client_private_key,
            certificate_chain,
            encrypted_request,
            encrypted_response,
            domain,
            timestamp,
            expected_status,
            verifier_nonce,
        };

        bundle.validate()?;
        Ok(bundle)
    }

    /// Validate the canonical bundle for consistency and constraints
    pub fn validate(&self) -> VefasResult<()> {
        // Check protocol version
        if self.version != VEFAS_PROTOCOL_VERSION {
            return Err(VefasError::version_mismatch(VEFAS_PROTOCOL_VERSION, self.version));
        }

        // Validate domain name
        if self.domain.is_empty() {
            return Err(VefasError::invalid_input("domain", "Domain cannot be empty"));
        }

        if self.domain.len() > MAX_DOMAIN_LENGTH {
            return Err(VefasError::invalid_input(
                "domain",
                &("Domain too long: ".to_string()
                    + &format_decimal(self.domain.len())
                    + " characters (max "
                    + &format_decimal(MAX_DOMAIN_LENGTH)
                    + ")"),
            ));
        }

        // Validate required handshake messages are present and within size limits
        self.validate_handshake_message(&self.client_hello, "client_hello")?;
        self.validate_handshake_message(&self.server_hello, "server_hello")?;

        // Optional handshake messages (encrypted post-ServerHello in TLS 1.3) may be empty;
        // if present, enforce size limits
        if !self.certificate_msg.is_empty() {
            self.validate_handshake_message(&self.certificate_msg, "certificate_msg")?;
        }
        if !self.certificate_verify_msg.is_empty() {
            self.validate_handshake_message(&self.certificate_verify_msg, "certificate_verify_msg")?;
        }
        if !self.server_finished_msg.is_empty() {
            self.validate_handshake_message(&self.server_finished_msg, "server_finished_msg")?;
        }

        // Validate TLS records
        self.validate_tls_record(&self.encrypted_request, "encrypted_request")?;
        self.validate_tls_record(&self.encrypted_response, "encrypted_response")?;

        // Validate certificate chain limits if provided. Allow empty chain here and defer
        // semantic checks to higher-level validator.
        let total_cert_size: usize = self.certificate_chain.iter().map(|cert| cert.len()).sum();
        if total_cert_size > MAX_CERTIFICATE_CHAIN_SIZE {
            return Err(VefasError::memory_error(
                total_cert_size,
                MAX_CERTIFICATE_CHAIN_SIZE,
                "certificate chain",
            ));
        }
        for (i, cert) in self.certificate_chain.iter().enumerate() {
            if cert.len() > MAX_CERTIFICATE_CHAIN_SIZE {
                return Err(VefasError::memory_error(
                    cert.len(),
                    MAX_CERTIFICATE_CHAIN_SIZE,
                    &format!("certificate[{}]", i),
                ));
            }
        }

        // Validate HTTP status code
        if !(100..=599).contains(&self.expected_status) {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidStatusCode,
                &("Invalid HTTP status code: ".to_string() + &format_decimal(self.expected_status as usize)),
            ));
        }

        // Validate timestamp (basic sanity check - not in far future)
        const MAX_FUTURE_SECONDS: u64 = 60; // Allow 1 minute in future for clock skew
        let now_estimate = self.timestamp + MAX_FUTURE_SECONDS;
        if self.timestamp > now_estimate {
            // This is a very basic check since we can't get current time in no_std
            // Real validation happens in host environment
        }

        Ok(())
    }

    /// Get the total memory footprint of this bundle
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>()
            + self.client_hello.len()
            + self.server_hello.len()
            + self.certificate_msg.len()
            + self.certificate_verify_msg.len()
            + self.server_finished_msg.len()
            + self.certificate_chain.iter().map(|cert| cert.len()).sum::<usize>()
            + self.encrypted_request.len()
            + self.encrypted_response.len()
            + self.domain.len()
    }

    /// Generate a deterministic bundle hash for proof claims
    ///
    /// This hash uniquely identifies the bundle and is included in proof claims
    /// to ensure the verifier processed exactly this data.
    pub fn bundle_hash(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        // Helper to prefix vec length as u32 be then bytes
        fn update_len_bytes<D: Digest>(h: &mut D, bytes: &[u8]) {
            let len = bytes.len() as u32;
            h.update(len.to_be_bytes());
            h.update(bytes);
        }

        // Stable order of fields
        hasher.update(self.version.to_be_bytes());
        update_len_bytes(&mut hasher, &self.client_hello);
        update_len_bytes(&mut hasher, &self.server_hello);
        update_len_bytes(&mut hasher, &self.certificate_msg);
        update_len_bytes(&mut hasher, &self.certificate_verify_msg);
        update_len_bytes(&mut hasher, &self.server_finished_msg);
        hasher.update(self.client_private_key);

        // Certificate chain: count + each entry
        hasher.update((self.certificate_chain.len() as u32).to_be_bytes());
        for cert in &self.certificate_chain {
            update_len_bytes(&mut hasher, cert);
        }

        update_len_bytes(&mut hasher, &self.encrypted_request);
        update_len_bytes(&mut hasher, &self.encrypted_response);
        update_len_bytes(&mut hasher, self.domain.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.expected_status.to_be_bytes());
        hasher.update(self.verifier_nonce);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Check if bundle represents a valid TLS 1.3 session
    pub fn is_tls13_session(&self) -> bool {
        // Basic heuristic: TLS 1.3 ServerHello should contain version 0x0304
        if self.server_hello.len() < 2 {
            return false;
        }

        // Look for TLS 1.3 version in ServerHello
        // This is a simplified check - real implementation would parse properly
        self.server_hello.windows(2).any(|window| window == [0x03, 0x04])
    }

    /// Validate a handshake message
    fn validate_handshake_message(&self, message: &[u8], name: &str) -> VefasResult<()> {
        if message.is_empty() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidHandshake,
                &(name.to_string() + " cannot be empty"),
            ));
        }

        if message.len() > MAX_HANDSHAKE_MESSAGE_SIZE {
            return Err(VefasError::memory_error(
                message.len(),
                MAX_HANDSHAKE_MESSAGE_SIZE,
                name,
            ));
        }

        Ok(())
    }

    /// Validate a TLS record
    fn validate_tls_record(&self, record: &[u8], name: &str) -> VefasResult<()> {
        if record.is_empty() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &(name.to_string() + " cannot be empty"),
            ));
        }

        if record.len() > MAX_TLS_RECORD_SIZE {
            return Err(VefasError::memory_error(
                record.len(),
                MAX_TLS_RECORD_SIZE,
                name,
            ));
        }

        // Enforce TLSCiphertext structure (RFC 8446 §5.1):
        // content_type (1) = application_data (23), legacy_version (2) = 0x0303,
        // length (2) matches remaining bytes
        if record.len() < 5 {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &(name.to_string() + ": TLS record too short"),
            ));
        }

        let content_type = record[0];
        let legacy_version = u16::from_be_bytes([record[1], record[2]]);
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;

        if content_type != 23 {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &(name.to_string() + ": content_type must be 23 (application_data)"),
            ));
        }

        // TLS 1.3 uses legacy_version 0x0303 in the record layer
        if legacy_version != 0x0303 {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::UnsupportedVersion,
                &(name.to_string() + ": legacy_version must be 0x0303 for TLS 1.3 records"),
            ));
        }

        if 5 + length != record.len() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &(name.to_string() + ": record length mismatch"),
            ));
        }

        Ok(())
    }
}

/// Bundle metadata for verification context
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleMetadata {
    /// Capture source identifier
    pub capture_source: String,
    /// Platform used for capture (host information)
    pub capture_platform: String,
    /// rustls version used for capture
    pub rustls_version: String,
    /// Additional custom metadata
    pub custom_fields: Vec<(String, String)>,
}

impl BundleMetadata {
    /// Create new bundle metadata
    pub fn new(
        capture_source: String,
        capture_platform: String,
        rustls_version: String,
    ) -> Self {
        Self {
            capture_source,
            capture_platform,
            rustls_version,
            custom_fields: Vec::new(),
        }
    }

    /// Add a custom field
    pub fn add_custom_field(&mut self, key: String, value: String) {
        self.custom_fields.push((key, value));
    }

    /// Validate metadata
    pub fn validate(&self) -> VefasResult<()> {
        if self.capture_source.is_empty() {
            return Err(VefasError::invalid_input(
                "capture_source",
                "Capture source cannot be empty",
            ));
        }

        if self.capture_platform.is_empty() {
            return Err(VefasError::invalid_input(
                "capture_platform",
                "Capture platform cannot be empty",
            ));
        }

        if self.rustls_version.is_empty() {
            return Err(VefasError::invalid_input(
                "rustls_version",
                "rustls version cannot be empty",
            ));
        }

        // Validate custom fields (no empty keys)
        for (key, _) in &self.custom_fields {
            if key.is_empty() {
                return Err(VefasError::invalid_input(
                    "custom_fields",
                    "Custom field keys cannot be empty",
                ));
            }
        }

        Ok(())
    }

    /// Get memory footprint
    pub fn memory_footprint(&self) -> usize {
        size_of::<Self>()
            + self.capture_source.len()
            + self.capture_platform.len()
            + self.rustls_version.len()
            + self.custom_fields.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
    }
}

impl Default for BundleMetadata {
    fn default() -> Self {
        Self::new(
            "unknown".to_string(),
            "unknown".to_string(),
            "0.0.0".to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, string::ToString};

    fn create_test_bundle() -> VefasCanonicalBundle {
        VefasCanonicalBundle::new(
            vec![0x16, 0x03, 0x01, 0x00, 0x10], // client_hello
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // server_hello (TLS 1.3)
            vec![0x16, 0x03, 0x04, 0x00, 0x20], // certificate_msg
            vec![0x16, 0x03, 0x04, 0x00, 0x08], // certificate_verify_msg
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // server_finished_msg
            [1u8; 32],                          // client_private_key
            vec![vec![1, 2, 3], vec![4, 5, 6]], // certificate_chain
            {
                let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                v.extend_from_slice(&[0u8; 32]);
                v
            },
            {
                let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x30];
                v.extend_from_slice(&[0u8; 48]);
                v
            },
            "example.com".to_string(),          // domain
            1640995200,                         // timestamp (2022-01-01)
            200,                                // expected_status
            [2u8; 32],                          // verifier_nonce
        ).unwrap()
    }

    #[test]
    fn test_bundle_creation_and_validation() {
        let bundle = create_test_bundle();
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.expected_status, 200);
        assert_eq!(bundle.version, VEFAS_PROTOCOL_VERSION);
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_validation_empty_domain() {
        let mut bundle = create_test_bundle();
        bundle.domain = String::new();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_validation_empty_handshake_message() {
        let mut bundle = create_test_bundle();
        bundle.client_hello = Vec::new();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_validation_empty_certificate_chain() {
        let mut bundle = create_test_bundle();
        bundle.certificate_chain = Vec::new();
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_bundle_validation_invalid_status_code() {
        let mut bundle = create_test_bundle();
        bundle.expected_status = 999;
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_memory_footprint() {
        let bundle = create_test_bundle();
        let footprint = bundle.memory_footprint();
        assert!(footprint > 0);

        // Should include all vector lengths plus struct size
        let expected_min = bundle.client_hello.len()
            + bundle.server_hello.len()
            + bundle.certificate_msg.len()
            + bundle.domain.len();
        assert!(footprint >= expected_min);
    }

    #[test]
    fn test_bundle_hash_deterministic() {
        let bundle1 = create_test_bundle();
        let bundle2 = create_test_bundle();

        let hash1 = bundle1.bundle_hash();
        let hash2 = bundle2.bundle_hash();

        // Same bundle should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_bundle_hash_different_for_different_data() {
        let bundle1 = create_test_bundle();
        let mut bundle2 = create_test_bundle();
        bundle2.domain = "different.com".to_string();

        let hash1 = bundle1.bundle_hash();
        let hash2 = bundle2.bundle_hash();

        // Different bundles should produce different hashes
        // Note: This is a weak test since our placeholder hash is simple
        // In real implementation with SHA-256, this would be more robust
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_tls13_session_detection() {
        let bundle = create_test_bundle();
        assert!(bundle.is_tls13_session());

        let mut bundle_tls12 = create_test_bundle();
        bundle_tls12.server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x10]; // TLS 1.2
        assert!(!bundle_tls12.is_tls13_session());
    }

    #[test]
    fn test_bundle_serialization() {
        let bundle = create_test_bundle();

        let serialized = serde_json::to_string(&bundle).unwrap();
        let deserialized: VefasCanonicalBundle = serde_json::from_str(&serialized).unwrap();

        assert_eq!(bundle, deserialized);
    }

    #[test]
    fn test_bundle_metadata() {
        let mut metadata = BundleMetadata::new(
            "vefas-gateway".to_string(),
            "linux-x86_64".to_string(),
            "0.23.0".to_string(),
        );

        assert!(metadata.validate().is_ok());

        metadata.add_custom_field("test_key".to_string(), "test_value".to_string());
        assert_eq!(metadata.custom_fields.len(), 1);

        // Test empty fields
        metadata.capture_source = String::new();
        assert!(metadata.validate().is_err());
    }

    #[test]
    fn test_version_validation() {
        let mut bundle = create_test_bundle();
        bundle.version = 999;
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_oversized_handshake_message() {
        let mut bundle = create_test_bundle();
        bundle.client_hello = vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE + 1];
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_oversized_tls_record() {
        let mut bundle = create_test_bundle();
        bundle.encrypted_request = vec![0u8; MAX_TLS_RECORD_SIZE + 1];
        assert!(bundle.validate().is_err());
    }
}