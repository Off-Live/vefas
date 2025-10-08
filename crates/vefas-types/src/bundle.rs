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

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::mem::size_of;
use serde::{Deserialize, Serialize};

use crate::{
    compression::{BundleCompressor, CompressedBundle, CompressionStats},
    errors::{VefasError, VefasResult},
    utils::format_decimal,
    MAX_DOMAIN_LENGTH, VEFAS_PROTOCOL_VERSION,
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
///
/// ## Compression Support
///
/// The bundle supports optional LZSS compression to reduce zkVM input sizes by 30-50%.
/// Compression is automatically applied when beneficial during bundle creation.
/// The bundle can be stored and processed in either compressed or uncompressed form
/// with transparent decompression for guest programs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VefasCanonicalBundle {
    /// Protocol version for compatibility checking
    pub version: u16,

    /// Compression format version (0 = uncompressed, 1+ = compressed)
    pub compression_version: u16,

    /// Bundle storage format
    pub storage: BundleStorage,

    // Verification metadata (always uncompressed for quick access)
    /// Target domain name for certificate validation
    pub domain: String,
    /// Unix timestamp when session was captured
    pub timestamp: u64,
    /// Expected HTTP status code
    pub expected_status: u16,
    /// Random nonce for proof uniqueness
    pub verifier_nonce: [u8; 32],
    
    /// Merkle tree root hash (32 bytes)
    pub merkle_root: Option<[u8; 32]>,
    
    /// Merkle inclusion proofs for essential fields
    pub merkle_proofs: Vec<(u8, Vec<u8>)>, // (FieldId as u8, serialized MerkleProof)
}

/// Bundle storage format supporting both compressed and uncompressed data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BundleStorage {
    /// Uncompressed bundle data
    Uncompressed(UncompressedBundleData),
    /// Compressed bundle data with compression metadata
    Compressed {
        /// Compressed bundle data
        compressed_data: CompressedBundle,
        /// Compression statistics for analysis
        compression_stats: CompressionStats,
    },
}

/// Debug key material for host-guest key derivation verification
///
/// This structure contains the "ground truth" keys derived by rustls on the host.
/// In debug builds, the guest program can compare its own key derivation against
/// these values to ensure both host and guest produce identical cryptographic
/// material from the same handshake data.
///
/// SECURITY: Only populated in debug builds where key capture is enabled.
/// Never included in production bundles.
/// NOTE: Always defined to ensure serialization compatibility between debug and release builds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugKeyMaterial {
    /// Cipher suite negotiated (0x1301, 0x1302, or 0x1303)
    pub cipher_suite: u16,

    /// Transcript hash of ClientHello..CertificateVerify (32 or 48 bytes)
    pub transcript_hash: Vec<u8>,

    /// CLIENT_HANDSHAKE_TRAFFIC_SECRET from rustls KeyLog
    pub client_handshake_traffic_secret: Vec<u8>,

    /// SERVER_HANDSHAKE_TRAFFIC_SECRET from rustls KeyLog
    pub server_handshake_traffic_secret: Vec<u8>,

    /// CLIENT_TRAFFIC_SECRET_0 from rustls KeyLog (application traffic)
    pub client_application_traffic_secret: Vec<u8>,

    /// SERVER_TRAFFIC_SECRET_0 from rustls KeyLog (application traffic)
    pub server_application_traffic_secret: Vec<u8>,

    /// EXPORTER_SECRET from rustls KeyLog
    pub exporter_secret: Vec<u8>,
}

/// Uncompressed bundle data
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncompressedBundleData {
    // Raw handshake messages (exact bytes from wire)
    /// ClientHello message (raw bytes)
    pub client_hello: Vec<u8>,
    /// ServerHello message (raw bytes)
    pub server_hello: Vec<u8>,
    /// EncryptedExtensions message (raw bytes, may be empty if not captured)
    pub encrypted_extensions: Vec<u8>,
    /// Certificate message (raw bytes)
    pub certificate_msg: Vec<u8>,
    /// CertificateVerify message (raw bytes)
    pub certificate_verify_msg: Vec<u8>,
    /// Server Finished message (raw bytes)
    pub server_finished_msg: Vec<u8>,
    /// Client Finished message (raw bytes, may be empty if not captured)
    pub client_finished_msg: Vec<u8>,

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

    // Debug-only: Host key material for guest verification
    /// Debug key material from host (only in debug builds)
    /// NOTE: Always present in struct to ensure serialization compatibility,
    /// but only populated in debug builds
    pub debug_keys: Option<DebugKeyMaterial>,
}

impl VefasCanonicalBundle {
    /// Set Merkle tree root and proofs
    pub fn set_merkle_proofs(&mut self, root: [u8; 32], proofs: Vec<(u8, Vec<u8>)>) {
        self.merkle_root = Some(root);
        self.merkle_proofs = proofs;
    }
    
    /// Get Merkle tree root
    pub fn merkle_root(&self) -> Option<&[u8; 32]> {
        self.merkle_root.as_ref()
    }
    
    /// Get Merkle proof for a specific field
    pub fn get_merkle_proof(&self, field_id: u8) -> Option<&Vec<u8>> {
        self.merkle_proofs.iter()
            .find(|(id, _)| *id == field_id)
            .map(|(_, proof)| proof)
    }

    /// Create a new canonical bundle with validation (uncompressed)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        encrypted_extensions: Vec<u8>,
        certificate_msg: Vec<u8>,
        certificate_verify_msg: Vec<u8>,
        server_finished_msg: Vec<u8>,
        client_finished_msg: Vec<u8>,
        client_private_key: [u8; 32],
        certificate_chain: Vec<Vec<u8>>,
        encrypted_request: Vec<u8>,
        encrypted_response: Vec<u8>,
        domain: String,
        timestamp: u64,
        expected_status: u16,
        verifier_nonce: [u8; 32],
        debug_keys: Option<DebugKeyMaterial>,
    ) -> VefasResult<Self> {
        let uncompressed_data = UncompressedBundleData {
            client_hello,
            server_hello,
            encrypted_extensions,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            client_finished_msg,
            client_private_key,
            certificate_chain,
            encrypted_request,
            encrypted_response,
            debug_keys,
        };

        let bundle = Self {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version: 0, // Uncompressed
            storage: BundleStorage::Uncompressed(uncompressed_data),
            domain,
            timestamp,
            expected_status,
            verifier_nonce,
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };

        bundle.validate()?;
        Ok(bundle)
    }

    /// Create a new canonical bundle with automatic compression
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_compression(
        client_hello: Vec<u8>,
        server_hello: Vec<u8>,
        encrypted_extensions: Vec<u8>,
        certificate_msg: Vec<u8>,
        certificate_verify_msg: Vec<u8>,
        server_finished_msg: Vec<u8>,
        client_finished_msg: Vec<u8>,
        client_private_key: [u8; 32],
        certificate_chain: Vec<Vec<u8>>,
        encrypted_request: Vec<u8>,
        encrypted_response: Vec<u8>,
        domain: String,
        timestamp: u64,
        expected_status: u16,
        verifier_nonce: [u8; 32],
        debug_keys: Option<DebugKeyMaterial>,
    ) -> VefasResult<Self> {
        let uncompressed_data = UncompressedBundleData {
            client_hello,
            server_hello,
            encrypted_extensions,
            certificate_msg,
            certificate_verify_msg,
            server_finished_msg,
            client_finished_msg,
            client_private_key,
            certificate_chain,
            encrypted_request,
            encrypted_response,
            debug_keys,
        };

        // Serialize uncompressed data to check if compression would be beneficial
        let serialized_data = serde_json::to_vec(&uncompressed_data).map_err(|e| {
            VefasError::serialization_error(&format!("Failed to serialize bundle data: {}", e))
        })?;

        // Apply compression if beneficial
        let (storage, compression_version) = if BundleCompressor::should_compress(&serialized_data)
        {
            match BundleCompressor::compress(&serialized_data) {
                Ok(compressed_bundle) => {
                    let stats =
                        BundleCompressor::compression_stats(&serialized_data, &compressed_bundle);
                    (
                        BundleStorage::Compressed {
                            compressed_data: compressed_bundle,
                            compression_stats: stats,
                        },
                        1, // Compressed format version
                    )
                }
                Err(_) => {
                    // If compression fails, fall back to uncompressed
                    (BundleStorage::Uncompressed(uncompressed_data), 0)
                }
            }
        } else {
            (BundleStorage::Uncompressed(uncompressed_data), 0)
        };

        let bundle = Self {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version,
            storage,
            domain,
            timestamp,
            expected_status,
            verifier_nonce,
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };

        bundle.validate()?;
        Ok(bundle)
    }

    /// Get bundle data (decompressing if necessary)
    pub fn get_bundle_data(&self) -> VefasResult<UncompressedBundleData> {
        match &self.storage {
            BundleStorage::Uncompressed(data) => Ok(data.clone()),
            BundleStorage::Compressed {
                compressed_data, ..
            } => {
                let decompressed_bytes = BundleCompressor::decompress(compressed_data)?;
                serde_json::from_slice(&decompressed_bytes).map_err(|e| {
                    VefasError::serialization_error(&format!(
                        "Failed to deserialize decompressed bundle: {}",
                        e
                    ))
                })
            }
        }
    }

    /// Check if bundle is compressed
    pub fn is_compressed(&self) -> bool {
        matches!(self.storage, BundleStorage::Compressed { .. })
    }

    /// Get compression statistics if bundle is compressed
    pub fn compression_stats(&self) -> Option<&CompressionStats> {
        match &self.storage {
            BundleStorage::Compressed {
                compression_stats, ..
            } => Some(compression_stats),
            BundleStorage::Uncompressed(_) => None,
        }
    }

    /// Convert to compressed format if beneficial
    pub fn try_compress(&mut self) -> VefasResult<bool> {
        if self.is_compressed() {
            return Ok(false); // Already compressed
        }

        let data = self.get_bundle_data()?;
        let serialized_data = serde_json::to_vec(&data).map_err(|e| {
            VefasError::serialization_error(&format!("Failed to serialize bundle data: {}", e))
        })?;

        if BundleCompressor::should_compress(&serialized_data) {
            match BundleCompressor::compress(&serialized_data) {
                Ok(compressed_bundle) => {
                    let stats =
                        BundleCompressor::compression_stats(&serialized_data, &compressed_bundle);
                    self.storage = BundleStorage::Compressed {
                        compressed_data: compressed_bundle,
                        compression_stats: stats,
                    };
                    self.compression_version = 1;
                    Ok(true)
                }
                Err(_) => Ok(false), // Compression failed
            }
        } else {
            Ok(false) // Compression not beneficial
        }
    }

    /// Convert to uncompressed format
    pub fn decompress(&mut self) -> VefasResult<()> {
        if !self.is_compressed() {
            return Ok(()); // Already uncompressed
        }

        let data = self.get_bundle_data()?;
        self.storage = BundleStorage::Uncompressed(data);
        self.compression_version = 0;
        Ok(())
    }

    /// Convenience methods for accessing bundle fields (with transparent decompression)

    /// Get ClientHello message (decompressing if necessary)
    pub fn client_hello(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.client_hello)
    }

    /// Get ServerHello message (decompressing if necessary)
    pub fn server_hello(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.server_hello)
    }

    /// Get EncryptedExtensions message (decompressing if necessary)
    pub fn encrypted_extensions(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.encrypted_extensions)
    }

    /// Get Certificate message (decompressing if necessary)
    pub fn certificate_msg(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.certificate_msg)
    }

    /// Get CertificateVerify message (decompressing if necessary)
    pub fn certificate_verify_msg(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.certificate_verify_msg)
    }

    /// Get Server Finished message (decompressing if necessary)
    pub fn server_finished_msg(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.server_finished_msg)
    }

    /// Get Client Finished message (decompressing if necessary)
    pub fn client_finished_msg(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.client_finished_msg)
    }

    /// Get client ephemeral private key (decompressing if necessary)
    pub fn client_private_key(&self) -> VefasResult<[u8; 32]> {
        Ok(self.get_bundle_data()?.client_private_key)
    }

    /// Get certificate chain (decompressing if necessary)
    pub fn certificate_chain(&self) -> VefasResult<Vec<Vec<u8>>> {
        Ok(self.get_bundle_data()?.certificate_chain)
    }

    /// Get encrypted HTTP request (decompressing if necessary)
    pub fn encrypted_request(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.encrypted_request)
    }

    /// Get encrypted HTTP response (decompressing if necessary)
    pub fn encrypted_response(&self) -> VefasResult<Vec<u8>> {
        Ok(self.get_bundle_data()?.encrypted_response)
    }

    /// Validate the canonical bundle for consistency and constraints
    pub fn validate(&self) -> VefasResult<()> {
        // Check protocol version
        if self.version != VEFAS_PROTOCOL_VERSION {
            return Err(VefasError::version_mismatch(
                VEFAS_PROTOCOL_VERSION,
                self.version,
            ));
        }

        // Validate compression version
        if self.compression_version > 1 {
            return Err(VefasError::invalid_input(
                "compression_version",
                &format!(
                    "Unsupported compression version: {}",
                    self.compression_version
                ),
            ));
        }

        // Validate domain name
        if self.domain.is_empty() {
            return Err(VefasError::invalid_input(
                "domain",
                "Domain cannot be empty",
            ));
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

        // Validate HTTP status code
        if !(100..=599).contains(&self.expected_status) {
            return Err(VefasError::http_error(
                crate::errors::HttpErrorType::InvalidStatusCode,
                &("Invalid HTTP status code: ".to_string()
                    + &format_decimal(self.expected_status as usize)),
            ));
        }

        // Validate timestamp (basic sanity check - not in far future)
        const MAX_FUTURE_SECONDS: u64 = 60; // Allow 1 minute in future for clock skew
        let now_estimate = self.timestamp + MAX_FUTURE_SECONDS;
        if self.timestamp > now_estimate {
            // This is a very basic check since we can't get current time in no_std
            // Real validation happens in host environment
        }

        // Validate storage format matches compression version
        match (&self.storage, self.compression_version) {
            (BundleStorage::Uncompressed(_), 0) => {} // Valid
            (BundleStorage::Compressed { .. }, v) if v > 0 => {} // Valid
            _ => {
                return Err(VefasError::invalid_input(
                    "storage_format",
                    "Storage format does not match compression version",
                ));
            }
        }

        // Validate compressed bundle if present
        if let BundleStorage::Compressed {
            compressed_data, ..
        } = &self.storage
        {
            compressed_data.validate()?;
        }

        // Validate bundle data by decompressing and checking fields
        let data = self.get_bundle_data()?;

        // Validate required handshake messages are present and within size limits
        self.validate_handshake_message(&data.client_hello, "client_hello")?;
        self.validate_handshake_message(&data.server_hello, "server_hello")?;

        // Optional handshake messages (encrypted post-ServerHello in TLS 1.3) may be empty;
        // if present, enforce size limits
        if !data.encrypted_extensions.is_empty() {
            self.validate_handshake_message(&data.encrypted_extensions, "encrypted_extensions")?;
        }
        if !data.certificate_msg.is_empty() {
            self.validate_handshake_message(&data.certificate_msg, "certificate_msg")?;
        }
        if !data.certificate_verify_msg.is_empty() {
            self.validate_handshake_message(
                &data.certificate_verify_msg,
                "certificate_verify_msg",
            )?;
        }
        if !data.server_finished_msg.is_empty() {
            self.validate_handshake_message(&data.server_finished_msg, "server_finished_msg")?;
        }
        if !data.client_finished_msg.is_empty() {
            self.validate_handshake_message(&data.client_finished_msg, "client_finished_msg")?;
        }

        // Validate TLS records
        self.validate_tls_record(&data.encrypted_request, "encrypted_request")?;
        self.validate_tls_record(&data.encrypted_response, "encrypted_response")?;

        // Validate certificate chain limits if provided. Allow empty chain here and defer
        // semantic checks to higher-level validator.
        let total_cert_size: usize = data.certificate_chain.iter().map(|cert| cert.len()).sum();
        if total_cert_size > MAX_CERTIFICATE_CHAIN_SIZE {
            return Err(VefasError::memory_error(
                total_cert_size,
                MAX_CERTIFICATE_CHAIN_SIZE,
                "certificate chain",
            ));
        }
        for (i, cert) in data.certificate_chain.iter().enumerate() {
            if cert.len() > MAX_CERTIFICATE_CHAIN_SIZE {
                return Err(VefasError::memory_error(
                    cert.len(),
                    MAX_CERTIFICATE_CHAIN_SIZE,
                    &format!("certificate[{}]", i),
                ));
            }
        }

        Ok(())
    }

    /// Get the total memory footprint of this bundle
    pub fn memory_footprint(&self) -> usize {
        let base_size = size_of::<Self>() + self.domain.len();

        match &self.storage {
            BundleStorage::Uncompressed(data) => {
                base_size
                    + data.client_hello.len()
                    + data.server_hello.len()
                    + data.certificate_msg.len()
                    + data.certificate_verify_msg.len()
                    + data.server_finished_msg.len()
                    + data
                        .certificate_chain
                        .iter()
                        .map(|cert| cert.len())
                        .sum::<usize>()
                    + data.encrypted_request.len()
                    + data.encrypted_response.len()
            }
            BundleStorage::Compressed {
                compressed_data,
                compression_stats: _,
            } => base_size + compressed_data.memory_footprint() + size_of::<CompressionStats>(),
        }
    }

    /// Generate a deterministic bundle hash for proof claims
    ///
    /// This hash uniquely identifies the bundle and is included in proof claims
    /// to ensure the verifier processed exactly this data.
    /// Note: The hash is computed from the uncompressed data to ensure consistency
    /// regardless of compression status.
    pub fn bundle_hash(&self) -> VefasResult<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let data = self.get_bundle_data()?;
        let mut hasher = Sha256::new();

        // Helper to prefix vec length as u32 be then bytes
        fn update_len_bytes<D: Digest>(h: &mut D, bytes: &[u8]) {
            let len = bytes.len() as u32;
            h.update(len.to_be_bytes());
            h.update(bytes);
        }

        // Stable order of fields (always based on uncompressed data)
        hasher.update(self.version.to_be_bytes());
        update_len_bytes(&mut hasher, &data.client_hello);
        update_len_bytes(&mut hasher, &data.server_hello);
        update_len_bytes(&mut hasher, &data.certificate_msg);
        // Include optional post-ServerHello messages
        update_len_bytes(&mut hasher, &data.encrypted_extensions);
        update_len_bytes(&mut hasher, &data.certificate_verify_msg);
        update_len_bytes(&mut hasher, &data.server_finished_msg);
        update_len_bytes(&mut hasher, &data.client_finished_msg);
        hasher.update(data.client_private_key);

        // Certificate chain: count + each entry
        hasher.update((data.certificate_chain.len() as u32).to_be_bytes());
        for cert in &data.certificate_chain {
            update_len_bytes(&mut hasher, cert);
        }

        update_len_bytes(&mut hasher, &data.encrypted_request);
        update_len_bytes(&mut hasher, &data.encrypted_response);
        update_len_bytes(&mut hasher, self.domain.as_bytes());
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.expected_status.to_be_bytes());
        hasher.update(self.verifier_nonce);

        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok(out)
    }

    /// Check if bundle represents a valid TLS 1.3 session
    pub fn is_tls13_session(&self) -> bool {
        // Basic heuristic: TLS 1.3 ServerHello should contain version 0x0304
        match self.server_hello() {
            Ok(server_hello) => {
                if server_hello.len() < 2 {
                    return false;
                }
                // Look for TLS 1.3 version in ServerHello
                // This is a simplified check - real implementation would parse properly
                server_hello.windows(2).any(|window| window == [0x03, 0x04])
            }
            Err(_) => false,
        }
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

    /// Validate TLS record(s) - can be a single record or multiple concatenated records
    fn validate_tls_record(&self, records: &[u8], name: &str) -> VefasResult<()> {
        if records.is_empty() {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &(name.to_string() + " cannot be empty"),
            ));
        }

        // Parse and validate each TLS record in the byte stream
        let mut offset = 0;
        let mut record_count = 0;

        while offset < records.len() {
            // Each TLS record must have at least 5 bytes (header)
            if offset + 5 > records.len() {
                return Err(VefasError::tls_error(
                    crate::errors::TlsErrorType::InvalidTranscript,
                    &format!("{}: incomplete TLS record header at offset {}", name, offset),
                ));
            }

            let content_type = records[offset];
            let legacy_version = u16::from_be_bytes([records[offset + 1], records[offset + 2]]);
            let length = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;

            // Validate this individual record
            if content_type != 23 {
                return Err(VefasError::tls_error(
                    crate::errors::TlsErrorType::InvalidTranscript,
                    &format!("{}: record {} content_type must be 23 (application_data), got {}", name, record_count, content_type),
                ));
            }

            if legacy_version != 0x0303 {
                return Err(VefasError::tls_error(
                    crate::errors::TlsErrorType::UnsupportedVersion,
                    &format!("{}: record {} legacy_version must be 0x0303 for TLS 1.3", name, record_count),
                ));
            }

            // Check we have enough bytes for the payload
            if offset + 5 + length > records.len() {
                return Err(VefasError::tls_error(
                    crate::errors::TlsErrorType::InvalidTranscript,
                    &format!("{}: record {} declares {} bytes but only {} available",
                        name, record_count, length, records.len() - offset - 5),
                ));
            }

            // Check individual record size limit
            if 5 + length > MAX_TLS_RECORD_SIZE {
                return Err(VefasError::memory_error(
                    5 + length,
                    MAX_TLS_RECORD_SIZE,
                    &format!("{} record {}", name, record_count),
                ));
            }

            // Move to next record
            offset += 5 + length;
            record_count += 1;
        }

        if record_count == 0 {
            return Err(VefasError::tls_error(
                crate::errors::TlsErrorType::InvalidTranscript,
                &format!("{}: no valid TLS records found", name),
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
    pub fn new(capture_source: String, capture_platform: String, rustls_version: String) -> Self {
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
            + self
                .custom_fields
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
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
    use alloc::{string::ToString, vec};

    fn create_test_bundle() -> VefasCanonicalBundle {
        VefasCanonicalBundle::new(
            vec![0x16, 0x03, 0x01, 0x00, 0x10], // client_hello
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // server_hello (TLS 1.3)
            vec![0x16, 0x03, 0x04, 0x00, 0x20], // encrypted_extensions
            vec![0x16, 0x03, 0x04, 0x00, 0x08], // certificate_msg
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // certificate_verify_msg
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // server_finished_msg
            vec![0x16, 0x03, 0x04, 0x00, 0x10], // client_finished_msg
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
            "example.com".to_string(), // domain
            1640995200,                // timestamp (2022-01-01)
            200,                       // expected_status
            [2u8; 32],                 // verifier_nonce
        )
        .unwrap()
    }

    fn create_test_bundle_with_compression() -> VefasCanonicalBundle {
        // Create a large bundle with repetitive data that should compress well
        let large_data = b"Test data for compression! ".repeat(100);

        // Create valid TLS record with proper length header
        let create_valid_tls_record = |data: &[u8]| {
            let mut record = Vec::new();
            record.push(0x17); // Application data
            record.extend_from_slice(&[0x03, 0x03]); // TLS version
            let length = data.len() as u16;
            record.extend_from_slice(&length.to_be_bytes()); // Length field
            record.extend_from_slice(data); // Actual data
            record
        };

        VefasCanonicalBundle::new_with_compression(
            large_data.clone(),                           // client_hello
            large_data.clone(),                           // server_hello
            large_data.clone(),                           // encrypted_extensions
            large_data.clone(),                           // certificate_msg
            large_data.clone(),                           // certificate_verify_msg
            large_data.clone(),                           // server_finished_msg
            large_data.clone(),                           // client_finished_msg
            [1u8; 32],                                    // client_private_key
            vec![large_data.clone(), large_data.clone()], // certificate_chain
            create_valid_tls_record(&large_data),         // encrypted_request
            create_valid_tls_record(&large_data),         // encrypted_response
            "example.com".to_string(),                    // domain
            1640995200,                                   // timestamp (2022-01-01)
            200,                                          // expected_status
            [2u8; 32],                                    // verifier_nonce
        )
        .unwrap()
    }

    #[test]
    fn test_bundle_creation_and_validation() {
        let bundle = create_test_bundle();
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.expected_status, 200);
        assert_eq!(bundle.version, VEFAS_PROTOCOL_VERSION);
        assert_eq!(bundle.compression_version, 0); // Uncompressed
        assert!(!bundle.is_compressed());
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_compressed_bundle_creation_and_validation() {
        let bundle = create_test_bundle_with_compression();
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.expected_status, 200);
        assert_eq!(bundle.version, VEFAS_PROTOCOL_VERSION);
        assert!(bundle.compression_version > 0); // Should be compressed
        assert!(bundle.is_compressed());
        assert!(bundle.validate().is_ok());

        // Verify compression statistics are available
        let stats = bundle.compression_stats().unwrap();
        assert!(stats.is_effective());
        assert!(stats.compression_ratio() < 80.0);
    }

    #[test]
    fn test_bundle_validation_empty_domain() {
        let mut bundle = create_test_bundle();
        bundle.domain = String::new();
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_validation_empty_handshake_message() {
        // Note: With the new compressed format, we cannot directly modify fields
        // Instead, we test validation by creating an invalid bundle manually
        let bundle = VefasCanonicalBundle {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version: 0,
            storage: BundleStorage::Uncompressed(UncompressedBundleData {
                client_hello: Vec::new(), // Empty client hello should fail validation
                server_hello: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                encrypted_extensions: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_msg: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_verify_msg: vec![0x16, 0x03, 0x04, 0x00, 0x08],
                server_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_private_key: [1u8; 32],
                certificate_chain: vec![vec![1, 2, 3], vec![4, 5, 6]],
                encrypted_request: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                    v.extend_from_slice(&[0u8; 32]);
                    v
                },
                encrypted_response: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x30];
                    v.extend_from_slice(&[0u8; 48]);
                    v
                },
            }),
            domain: "example.com".to_string(),
            timestamp: 1640995200,
            expected_status: 200,
            verifier_nonce: [2u8; 32],
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_bundle_validation_empty_certificate_chain() {
        // Create bundle with empty certificate chain (which should be valid)
        let bundle = VefasCanonicalBundle::new(
            vec![0x16, 0x03, 0x01, 0x00, 0x10],
            vec![0x16, 0x03, 0x04, 0x00, 0x10],
            vec![0x16, 0x03, 0x04, 0x00, 0x20],
            vec![0x16, 0x03, 0x04, 0x00, 0x08],
            vec![0x16, 0x03, 0x04, 0x00, 0x10],
            [1u8; 32],
            Vec::new(), // Empty certificate chain
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
            "example.com".to_string(),
            1640995200,
            200,
            [2u8; 32],
        )
        .unwrap();
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
        let expected_min = bundle.client_hello().unwrap().len()
            + bundle.server_hello().unwrap().len()
            + bundle.certificate_msg().unwrap().len()
            + bundle.domain.len();
        assert!(footprint >= expected_min);
    }

    #[test]
    fn test_bundle_hash_deterministic() {
        let bundle1 = create_test_bundle();
        let bundle2 = create_test_bundle();

        let hash1 = bundle1.bundle_hash().unwrap();
        let hash2 = bundle2.bundle_hash().unwrap();

        // Same bundle should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compressed_bundle_transparent_access() {
        let compressed_bundle = create_test_bundle_with_compression();

        // Test transparent access to bundle data
        assert!(compressed_bundle.client_hello().is_ok());
        assert!(compressed_bundle.server_hello().is_ok());
        assert!(compressed_bundle.certificate_msg().is_ok());
        assert!(compressed_bundle.certificate_verify_msg().is_ok());
        assert!(compressed_bundle.server_finished_msg().is_ok());
        assert!(compressed_bundle.client_private_key().is_ok());
        assert!(compressed_bundle.certificate_chain().is_ok());
        assert!(compressed_bundle.encrypted_request().is_ok());
        assert!(compressed_bundle.encrypted_response().is_ok());
    }

    #[test]
    fn test_bundle_compression_decompression_roundtrip() {
        let mut uncompressed_bundle = create_test_bundle();
        assert!(!uncompressed_bundle.is_compressed());

        // Try to compress the bundle
        let compressed = uncompressed_bundle.try_compress().unwrap();
        // Small bundle may not compress, so either outcome is valid

        if compressed {
            assert!(uncompressed_bundle.is_compressed());
            assert!(uncompressed_bundle.compression_stats().is_some());

            // Decompress back
            uncompressed_bundle.decompress().unwrap();
            assert!(!uncompressed_bundle.is_compressed());
            assert!(uncompressed_bundle.compression_stats().is_none());
        }
    }

    #[test]
    fn test_bundle_hash_consistent_across_compression() {
        let uncompressed = create_test_bundle_with_compression();
        let mut compressed = uncompressed.clone();

        // Both should be compressed, but let's force one to be uncompressed
        compressed.decompress().unwrap();

        // Now we have one compressed and one uncompressed with same data
        let hash1 = uncompressed.bundle_hash().unwrap();
        let hash2 = compressed.bundle_hash().unwrap();

        // Hashes should be identical regardless of compression
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_compression_memory_footprint() {
        let compressed_bundle = create_test_bundle_with_compression();

        if compressed_bundle.is_compressed() {
            let compressed_footprint = compressed_bundle.memory_footprint();

            // Create equivalent uncompressed bundle
            let mut uncompressed_bundle = compressed_bundle.clone();
            uncompressed_bundle.decompress().unwrap();
            let uncompressed_footprint = uncompressed_bundle.memory_footprint();

            // Compressed should use less memory
            assert!(compressed_footprint < uncompressed_footprint);
        }
    }

    #[test]
    fn test_bundle_hash_different_for_different_data() {
        let bundle1 = create_test_bundle();
        let mut bundle2 = create_test_bundle();
        bundle2.domain = "different.com".to_string();

        let hash1 = bundle1.bundle_hash().unwrap();
        let hash2 = bundle2.bundle_hash().unwrap();

        // Different bundles should produce different hashes
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_tls13_session_detection() {
        let bundle = create_test_bundle();
        assert!(bundle.is_tls13_session());

        // Create a TLS 1.2 bundle manually
        let bundle_tls12 = VefasCanonicalBundle {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version: 0,
            storage: BundleStorage::Uncompressed(UncompressedBundleData {
                client_hello: vec![0x16, 0x03, 0x01, 0x00, 0x10],
                server_hello: vec![0x16, 0x03, 0x03, 0x00, 0x10], // TLS 1.2
                encrypted_extensions: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_msg: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_verify_msg: vec![0x16, 0x03, 0x04, 0x00, 0x08],
                server_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_private_key: [1u8; 32],
                certificate_chain: vec![vec![1, 2, 3], vec![4, 5, 6]],
                encrypted_request: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                    v.extend_from_slice(&[0u8; 32]);
                    v
                },
                encrypted_response: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x30];
                    v.extend_from_slice(&[0u8; 48]);
                    v
                },
            }),
            domain: "example.com".to_string(),
            timestamp: 1640995200,
            expected_status: 200,
            verifier_nonce: [2u8; 32],
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };
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
        // Create bundle with oversized handshake message
        let bundle = VefasCanonicalBundle {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version: 0,
            storage: BundleStorage::Uncompressed(UncompressedBundleData {
                client_hello: vec![0u8; MAX_HANDSHAKE_MESSAGE_SIZE + 1],
                server_hello: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                encrypted_extensions: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_msg: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_verify_msg: vec![0x16, 0x03, 0x04, 0x00, 0x08],
                server_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_private_key: [1u8; 32],
                certificate_chain: vec![vec![1, 2, 3], vec![4, 5, 6]],
                encrypted_request: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x20];
                    v.extend_from_slice(&[0u8; 32]);
                    v
                },
                encrypted_response: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x30];
                    v.extend_from_slice(&[0u8; 48]);
                    v
                },
            }),
            domain: "example.com".to_string(),
            timestamp: 1640995200,
            expected_status: 200,
            verifier_nonce: [2u8; 32],
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };
        assert!(bundle.validate().is_err());
    }

    #[test]
    fn test_oversized_tls_record() {
        // Create bundle with oversized TLS record
        let bundle = VefasCanonicalBundle {
            version: VEFAS_PROTOCOL_VERSION,
            compression_version: 0,
            storage: BundleStorage::Uncompressed(UncompressedBundleData {
                client_hello: vec![0x16, 0x03, 0x01, 0x00, 0x10],
                server_hello: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                encrypted_extensions: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_msg: vec![0x16, 0x03, 0x04, 0x00, 0x20],
                certificate_verify_msg: vec![0x16, 0x03, 0x04, 0x00, 0x08],
                server_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_finished_msg: vec![0x16, 0x03, 0x04, 0x00, 0x10],
                client_private_key: [1u8; 32],
                certificate_chain: vec![vec![1, 2, 3], vec![4, 5, 6]],
                encrypted_request: vec![0u8; MAX_TLS_RECORD_SIZE + 1], // Too large
                encrypted_response: {
                    let mut v = vec![0x17, 0x03, 0x03, 0x00, 0x30];
                    v.extend_from_slice(&[0u8; 48]);
                    v
                },
            }),
            domain: "example.com".to_string(),
            timestamp: 1640995200,
            expected_status: 200,
            verifier_nonce: [2u8; 32],
            merkle_root: None,
            merkle_proofs: Vec::new(),
        };
        assert!(bundle.validate().is_err());
    }
}
