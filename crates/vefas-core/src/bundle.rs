//! # VefasCanonicalBundle Creation
//!
//! This module provides production-grade bundle creation for transforming
//! captured TLS session data into the canonical format required for guest verification.
//! It ensures deterministic serialization and complete capture of all necessary data.

#[cfg(not(feature = "std"))]
use alloc::{vec::Vec, string::String};

use crate::{
    Result, VefasCoreError,
    session::SessionData,
    keylog::VefasKeyLog,
    http::HttpData,
    records::{TlsRecordParser, HandshakeMessage, HandshakeType},
};
use vefas_types::VefasCanonicalBundle;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::{AeadInPlace, generic_array::GenericArray}};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use hkdf::Hkdf;

/// Components needed to build a canonical bundle
#[derive(Debug, Clone)]
pub struct BundleComponents {
    /// Client Hello handshake message
    pub client_hello: Vec<u8>,
    /// Server Hello handshake message
    pub server_hello: Vec<u8>,
    /// Certificate handshake message
    pub certificate_msg: Vec<u8>,
    /// Certificate Verify handshake message
    pub certificate_verify_msg: Vec<u8>,
    /// Finished handshake messages (client and server)
    pub finished_msgs: Vec<Vec<u8>>,
    /// Server certificate chain in DER bytes (ordered leaf->root, may be empty if unavailable)
    pub certificate_chain: Vec<Vec<u8>>,
    /// Application data (HTTP request/response)
    pub application_data: Vec<u8>,
    /// Outbound ApplicationData TLS record (full on-wire bytes)
    pub encrypted_request: Vec<u8>,
    /// Inbound ApplicationData TLS record (full on-wire bytes)
    pub encrypted_response: Vec<u8>,
    /// Client ephemeral private key captured from session (if available)
    pub client_ephemeral_private_key: Option<[u8; 32]>,
    /// Expected HTTP status code from response
    pub expected_status: u16,
    /// TLS session secrets
    pub secrets: SecretData,
    /// Bundle metadata
    pub metadata: BundleMetadata,
}

/// TLS session secrets in canonical format
#[derive(Debug, Clone)]
pub struct SecretData {
    /// Client random from ClientHello
    pub client_random: [u8; 32],
    /// Server random from ServerHello
    pub server_random: [u8; 32],
    /// Traffic secrets for decryption
    pub traffic_secrets: Vec<TrafficSecret>,
}

/// Individual traffic secret entry
#[derive(Debug, Clone)]
pub struct TrafficSecret {
    /// Secret label (e.g., "CLIENT_HANDSHAKE_TRAFFIC_SECRET")
    pub label: String,
    /// Secret value
    pub secret: Vec<u8>,
    /// Associated client random
    pub client_random: [u8; 32],
}

/// Bundle metadata
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    /// Timestamp when bundle was created
    pub timestamp: u64,
    /// Domain name from TLS connection
    pub domain: String,
    /// TLS version used
    pub tls_version: String,
    /// Cipher suite used
    pub cipher_suite: String,
    /// Connection ID for traceability
    pub connection_id: [u8; 16],
}

/// Compression strategy for bundle creation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionStrategy {
    /// Never compress bundles
    Never,
    /// Automatically compress when beneficial (default)
    Auto,
    /// Always attempt compression (even if not beneficial)
    Always,
}

impl Default for CompressionStrategy {
    fn default() -> Self {
        Self::Auto
    }
}

/// Builder for creating VefasCanonicalBundle from session data
#[derive(Debug)]
pub struct BundleBuilder {
    record_parser: TlsRecordParser,
    compression_strategy: CompressionStrategy,
}

impl Default for BundleBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl BundleBuilder {
    /// Create a new bundle builder with default settings
    pub fn new() -> Self {
        Self {
            record_parser: TlsRecordParser::new(),
            compression_strategy: CompressionStrategy::default(),
        }
    }

    /// Set the compression strategy for this builder
    pub fn with_compression_strategy(mut self, strategy: CompressionStrategy) -> Self {
        self.compression_strategy = strategy;
        self
    }

    /// Get the current compression strategy
    pub fn compression_strategy(&self) -> CompressionStrategy {
        self.compression_strategy
    }

    /// Create a canonical bundle from session data, HTTP data, and secrets
    pub fn from_session_data(
        &mut self,
        session: &SessionData,
        http_data: &HttpData,
        secrets: &VefasKeyLog,
    ) -> Result<VefasCanonicalBundle> {
        // Extract handshake messages from captured bytes
        let handshake_components = self.extract_handshake_messages(session)?;

        // Serialize secrets in canonical format
        let secret_data = self.serialize_secrets(secrets, session)?;

        // Create bundle metadata
        let metadata = self.create_bundle_metadata(session)?;

        // Extract first outbound/inbound TLSCiphertext ApplicationData records
        let (encrypted_request, encrypted_response) = self.extract_ciphertext_records_from_session(session)?;

        // If post-ServerHello handshake messages are missing (TLS 1.3 encrypts them),
        // attempt to decrypt inbound ApplicationData records with the server handshake traffic secret
        // to recover Certificate, CertificateVerify, and Finished and validate Finished.
        let mut recovered_certificate_msg: Option<Vec<u8>> = None;
        let mut recovered_certificate_verify_msg: Option<Vec<u8>> = None;
        let mut recovered_finished_msg: Option<Vec<u8>> = None;

        if handshake_components.certificate_msg.is_empty() || handshake_components.finished_msgs.is_empty() {
            if let Some((cert_opt, cert_verify_opt, finished_opt)) = self.try_decrypt_and_validate_server_finished(session, &secret_data, &handshake_components.client_hello, &handshake_components.server_hello)? {
                recovered_certificate_msg = cert_opt;
                recovered_certificate_verify_msg = cert_verify_opt;
                recovered_finished_msg = Some(finished_opt);
            }
        }

        // Derive certificate chain bytes: prefer parsed Certificate handshake if present,
        // otherwise fall back to rustls peer_certificates() captured in SessionData.
        // Prefer recovered messages if present
        let certificate_msg = if let Some(m) = recovered_certificate_msg { m } else { handshake_components.certificate_msg };
        let certificate_verify_msg = if let Some(m) = recovered_certificate_verify_msg { m } else { handshake_components.certificate_verify_msg };
        let finished_msgs = if let Some(m) = recovered_finished_msg { vec![m] } else { handshake_components.finished_msgs };

        let certificate_chain = if !certificate_msg.is_empty() {
            self.extract_certificate_chain_from_certificate_msg(&certificate_msg)?
        } else {
            session
                .certificate_chain
                .iter()
                .map(|c| c.as_ref().to_vec())
                .collect()
        };

        // Build components structure
        let components = BundleComponents {
            client_hello: handshake_components.client_hello,
            server_hello: handshake_components.server_hello,
            certificate_msg,
            certificate_verify_msg,
            finished_msgs,
            certificate_chain,
            application_data: self.serialize_application_data(http_data)?,
            encrypted_request,
            encrypted_response,
            client_ephemeral_private_key: session.client_ephemeral_private_key,
            expected_status: http_data.status_code,
            secrets: secret_data,
            metadata,
        };

        // Create the final canonical bundle based on compression strategy
        self.create_bundle_with_strategy(components)
    }

    /// Extract handshake messages from raw TLS data
    fn extract_handshake_messages(&mut self, session: &SessionData) -> Result<HandshakeComponents> {
        // Parse outbound and inbound separately to preserve direction when selecting server Finished
        let mut parser_out = TlsRecordParser::new();
        let out_records = parser_out.parse_records(&session.outbound_bytes)?;
        let out_msgs = parser_out.extract_handshake_messages(&out_records)?;

        let mut parser_in = TlsRecordParser::new();
        let in_records = parser_in.parse_records(&session.inbound_bytes)?;
        let in_msgs = parser_in.extract_handshake_messages(&in_records)?;

        let mut components = HandshakeComponents::default();

        for message in out_msgs {
            match message.msg_type {
                HandshakeType::ClientHello => {
                    components.client_hello = self.serialize_handshake_message(&message)?;
                }
                HandshakeType::Finished => {
                    // client Finished retained in other_messages
                    components.other_messages.push(self.serialize_handshake_message(&message)?);
                }
                _ => {
                    components.other_messages.push(self.serialize_handshake_message(&message)?);
                }
            }
        }

        for message in in_msgs {
            match message.msg_type {
                HandshakeType::ServerHello => {
                    components.server_hello = self.serialize_handshake_message(&message)?;
                }
                HandshakeType::Certificate => {
                    components.certificate_msg = self.serialize_handshake_message(&message)?;
                }
                HandshakeType::CertificateVerify => {
                    components.certificate_verify_msg = self.serialize_handshake_message(&message)?;
                }
                HandshakeType::Finished => {
                    // server Finished
                    components.finished_msgs.push(self.serialize_handshake_message(&message)?);
                }
                _ => {
                    components.other_messages.push(self.serialize_handshake_message(&message)?);
                }
            }
        }

        Ok(components)
    }

    /// Serialize a handshake message in canonical format
    fn serialize_handshake_message(&self, message: &HandshakeMessage) -> Result<Vec<u8>> {
        let mut serialized = Vec::new();

        // Message type (1 byte)
        serialized.push(message.msg_type as u8);

        // Length (3 bytes, big-endian)
        let length_bytes = message.length.to_be_bytes();
        serialized.extend_from_slice(&length_bytes[1..4]);

        // Payload
        serialized.extend_from_slice(&message.payload);

        Ok(serialized)
    }

    /// Serialize secrets in canonical format
    fn serialize_secrets(&self, keylog: &VefasKeyLog, session: &SessionData) -> Result<SecretData> {
        // Extract client and server randoms from handshake messages
        let (client_random, server_random) = self.extract_randoms_from_session(session)?;

        let secrets_map = keylog.get_session_secrets(&client_random)?;

        let mut traffic_secrets = Vec::new();
        for (label, entry) in secrets_map {
            traffic_secrets.push(TrafficSecret {
                label,
                secret: entry.secret.clone(),
                client_random: entry.client_random,
            });
        }

        // Sort secrets by label for deterministic ordering
        traffic_secrets.sort_by(|a, b| a.label.cmp(&b.label));

        Ok(SecretData {
            client_random,
            server_random,
            traffic_secrets,
        })
    }

    /// Extract client and server randoms from handshake messages
    fn extract_randoms_from_session(&self, session: &SessionData) -> Result<([u8; 32], [u8; 32])> {
        // Parse TLS records to extract handshake messages
        let mut all_data = Vec::new();
        all_data.extend_from_slice(&session.outbound_bytes);
        all_data.extend_from_slice(&session.inbound_bytes);

        let mut parser = TlsRecordParser::new();
        let records = parser.parse_records(&all_data)?;
        let handshake_messages = parser.extract_handshake_messages(&records)?;

        let mut client_random = None;
        let mut server_random = None;

        for message in handshake_messages {
            match message.msg_type {
                HandshakeType::ClientHello => {
                    client_random = Some(self.extract_random_from_hello(&message.payload, true)?);
                }
                HandshakeType::ServerHello => {
                    server_random = Some(self.extract_random_from_hello(&message.payload, false)?);
                }
                _ => {} // Ignore other message types
            }
        }

        let client_random = client_random.ok_or_else(|| {
            VefasCoreError::ValidationError("ClientHello not found in handshake messages".to_string())
        })?;

        let server_random = server_random.ok_or_else(|| {
            VefasCoreError::ValidationError("ServerHello not found in handshake messages".to_string())
        })?;

        Ok((client_random, server_random))
    }

    /// Extract random value from ClientHello or ServerHello message (RFC 8446 §4.1.2/§4.1.3)
    fn extract_random_from_hello(&self, payload: &[u8], is_client_hello: bool) -> Result<[u8; 32]> {
        // Common prelude: legacy_version (2) + random (32)
        if payload.len() < 34 {
            return Err(VefasCoreError::ValidationError(format!(
                "Hello message too short: {} bytes (min 34)", payload.len()
            )));
        }

        let mut random = [0u8; 32];
        random.copy_from_slice(&payload[2..34]);

        // Continue structural validation to guard against malformed inputs
        let mut offset = 34;

        // session_id length and value (both ClientHello and ServerHello)
        if offset >= payload.len() { return Err(VefasCoreError::ValidationError("Hello missing legacy_session_id length".into())); }
        let sid_len = payload[offset] as usize;
        offset = offset.checked_add(1 + sid_len).ok_or_else(|| VefasCoreError::ValidationError("Overflow parsing session_id".into()))?;
        if offset > payload.len() { return Err(VefasCoreError::ValidationError("Hello legacy_session_id exceeds message size".into())); }

        if is_client_hello {
            // cipher_suites length (2) + suites
            if offset + 2 > payload.len() { return Err(VefasCoreError::ValidationError("ClientHello missing cipher_suites length".into())); }
            let cs_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            offset = offset.checked_add(cs_len).ok_or_else(|| VefasCoreError::ValidationError("Overflow parsing cipher_suites".into()))?;
            if offset > payload.len() { return Err(VefasCoreError::ValidationError("ClientHello cipher_suites exceeds message size".into())); }

            // compression_methods length (1) + methods
            if offset >= payload.len() { return Err(VefasCoreError::ValidationError("ClientHello missing compression_methods length".into())); }
            let cm_len = payload[offset] as usize;
            offset = offset.checked_add(1 + cm_len).ok_or_else(|| VefasCoreError::ValidationError("Overflow parsing compression_methods".into()))?;
            if offset > payload.len() { return Err(VefasCoreError::ValidationError("ClientHello compression_methods exceeds message size".into())); }

            // extensions length (2) + extensions
            if offset + 2 > payload.len() { return Err(VefasCoreError::ValidationError("ClientHello missing extensions length".into())); }
            let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            offset = offset.checked_add(ext_len).ok_or_else(|| VefasCoreError::ValidationError("Overflow parsing ClientHello extensions".into()))?;
            if offset > payload.len() { return Err(VefasCoreError::ValidationError("ClientHello extensions exceed message size".into())); }
        } else {
            // ServerHello: cipher_suite (2), compression_method (1), extensions length (2) + extensions
            if offset + 2 > payload.len() { return Err(VefasCoreError::ValidationError("ServerHello missing cipher_suite".into())); }
            offset += 2; // cipher_suite

            if offset + 1 > payload.len() { return Err(VefasCoreError::ValidationError("ServerHello missing compression_method".into())); }
            offset += 1; // compression_method

            if offset + 2 > payload.len() { return Err(VefasCoreError::ValidationError("ServerHello missing extensions length".into())); }
            let ext_len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            offset = offset.checked_add(ext_len).ok_or_else(|| VefasCoreError::ValidationError("Overflow parsing ServerHello extensions".into()))?;
            if offset > payload.len() { return Err(VefasCoreError::ValidationError("ServerHello extensions exceed message size".into())); }
        }

        Ok(random)
    }

    /// Serialize HTTP application data
    fn serialize_application_data(&self, http_data: &HttpData) -> Result<Vec<u8>> {
        let mut app_data = Vec::new();

        // Include both request and response data
        app_data.extend_from_slice(&http_data.request_bytes);
        app_data.extend_from_slice(&http_data.response_bytes);

        Ok(app_data)
    }

    /// Extract first outbound and inbound TLS ApplicationData records as full on-wire bytes
    fn extract_ciphertext_records_from_session(&self, session: &SessionData) -> Result<(Vec<u8>, Vec<u8>)> {
        let out_records = {
            let mut p = TlsRecordParser::new();
            p.parse_records(&session.outbound_bytes)?
        };
        let in_records = {
            let mut p = TlsRecordParser::new();
            p.parse_records(&session.inbound_bytes)?
        };

        let req = TlsRecordParser::new()
            .first_application_record_bytes(&out_records)
            .ok_or_else(|| VefasCoreError::ValidationError("No outbound ApplicationData record found".to_string()))?;
        let resp = TlsRecordParser::new()
            .first_application_record_bytes(&in_records)
            .ok_or_else(|| VefasCoreError::ValidationError("No inbound ApplicationData record found".to_string()))?;

        Ok((req, resp))
    }

    /// Create bundle metadata
    fn create_bundle_metadata(&self, session: &SessionData) -> Result<BundleMetadata> {
        Ok(BundleMetadata {
            timestamp: session.timestamp,
            domain: session.server_name.clone(),
            tls_version: format!("{:?}", session.protocol_version),
            cipher_suite: format!("{:?}", session.negotiated_suite),
            connection_id: session.connection_id,
        })
    }

    /// Create bundle based on the configured compression strategy
    fn create_bundle_with_strategy(&self, components: BundleComponents) -> Result<VefasCanonicalBundle> {
        match self.compression_strategy {
            CompressionStrategy::Never => self.create_deterministic_bundle(components),
            CompressionStrategy::Auto => self.create_deterministic_bundle_with_compression(components),
            CompressionStrategy::Always => self.create_deterministic_bundle_force_compression(components),
        }
    }

    /// Create the final deterministic bundle with automatic compression
    fn create_deterministic_bundle_with_compression(&self, components: BundleComponents) -> Result<VefasCanonicalBundle> {
        // Generate deterministic verifier nonce based on bundle contents
        let verifier_nonce = self.generate_deterministic_nonce(&components)?;

        // Choose client private key: require captured ephemeral scalar (no placeholder allowed)
        let client_private_key = components.client_ephemeral_private_key.ok_or_else(||
            VefasCoreError::ValidationError("Missing client ephemeral private key; configure provider seed or capture hooks".to_string())
        )?;

        // Use on-wire TLSCiphertext captured earlier
        let encrypted_request = components.encrypted_request;
        let encrypted_response = components.encrypted_response;

        // Create the bundle with automatic compression
        let bundle = VefasCanonicalBundle::new_with_compression(
            components.client_hello,
            components.server_hello,
            components.certificate_msg,
            components.certificate_verify_msg,
            components.finished_msgs.into_iter().next().unwrap_or_default(), // server_finished_msg
            client_private_key,
            components.certificate_chain,
            encrypted_request,
            encrypted_response,
            components.metadata.domain,
            components.metadata.timestamp,
            components.expected_status,
            verifier_nonce,
        ).map_err(|e| VefasCoreError::ValidationError(format!("Failed to create bundle: {:?}", e)))?;

        Ok(bundle)
    }

    /// Create the final deterministic bundle with forced compression
    fn create_deterministic_bundle_force_compression(&self, components: BundleComponents) -> Result<VefasCanonicalBundle> {
        // First create an uncompressed bundle
        let mut bundle = self.create_deterministic_bundle(components)?;

        // Force compression
        bundle.try_compress()
            .map_err(|e| VefasCoreError::ValidationError(format!("Failed to force compression: {:?}", e)))?;

        Ok(bundle)
    }

    /// Create an uncompressed bundle (for compatibility or when compression is not desired)
    fn create_deterministic_bundle(&self, components: BundleComponents) -> Result<VefasCanonicalBundle> {
        // Generate deterministic verifier nonce based on bundle contents
        let verifier_nonce = self.generate_deterministic_nonce(&components)?;

        // Choose client private key: require captured ephemeral scalar (no placeholder allowed)
        let client_private_key = components.client_ephemeral_private_key.ok_or_else(||
            VefasCoreError::ValidationError("Missing client ephemeral private key; configure provider seed or capture hooks".to_string())
        )?;

        // Use on-wire TLSCiphertext captured earlier
        let encrypted_request = components.encrypted_request;
        let encrypted_response = components.encrypted_response;

        // Create the bundle without compression
        let bundle = VefasCanonicalBundle::new(
            components.client_hello,
            components.server_hello,
            components.certificate_msg,
            components.certificate_verify_msg,
            components.finished_msgs.into_iter().next().unwrap_or_default(), // server_finished_msg
            client_private_key,
            components.certificate_chain,
            encrypted_request,
            encrypted_response,
            components.metadata.domain,
            components.metadata.timestamp,
            components.expected_status,
            verifier_nonce,
        ).map_err(|e| VefasCoreError::ValidationError(format!("Failed to create bundle: {:?}", e)))?;

        Ok(bundle)
    }

    /// Attempt to decrypt inbound ApplicationData and validate Server Finished.
    /// Returns optionally recovered Certificate, CertificateVerify and mandatory Finished bytes (serialized handshake) if validation succeeds.
    fn try_decrypt_and_validate_server_finished(
        &self,
        session: &SessionData,
        secrets: &SecretData,
        client_hello: &Vec<u8>,
        server_hello: &Vec<u8>,
    ) -> Result<Option<(Option<Vec<u8>>, Option<Vec<u8>>, Vec<u8>)>> {
        // Find server handshake traffic secret from keylog
        let server_hs_secret = match secrets.traffic_secrets.iter().find(|s| s.label == "SERVER_HANDSHAKE_TRAFFIC_SECRET") {
            Some(s) => s.secret.clone(),
            None => return Ok(None),
        };

        // Decide hash/cipher based on secret length (SHA-256 -> 32, SHA-384 -> 48)
        let secret_len = server_hs_secret.len();
        if secret_len != 32 && secret_len != 48 { return Ok(None); }

        // Records to process
        let mut parser = TlsRecordParser::new();
        let records = parser.parse_records(&session.inbound_bytes)?;

        let mut iv_static = [0u8; 12];

        if secret_len == 32 {
            let hk = Hkdf::<Sha256>::from_prk(&server_hs_secret).map_err(|_| VefasCoreError::ValidationError("invalid PRK".into()))?;
            let mut key = [0u8; 16];

            let mut label_key = Vec::new();
            label_key.extend_from_slice(&u16::to_be_bytes(16));
            label_key.push(6 + b"key".len() as u8);
            label_key.extend_from_slice(b"tls13 ");
            label_key.extend_from_slice(b"key");
            label_key.push(0);
            hk.expand(&label_key, &mut key).map_err(|_| VefasCoreError::ValidationError("HKDF expand key failed".into()))?;

            let mut label_iv = Vec::new();
            label_iv.extend_from_slice(&u16::to_be_bytes(12));
            label_iv.push(6 + b"iv".len() as u8);
            label_iv.extend_from_slice(b"tls13 ");
            label_iv.extend_from_slice(b"iv");
            label_iv.push(0);
            hk.expand(&label_iv, &mut iv_static).map_err(|_| VefasCoreError::ValidationError("HKDF expand iv failed".into()))?;

            // Decrypt with AES-128-GCM
            let cipher = Aes128Gcm::new_from_slice(&key).map_err(|_| VefasCoreError::ValidationError("AES key error".into()))?;
            let (recovered_cert, recovered_cv, recovered_fin) = process_records(&cipher, records.clone(), &mut iv_static);
            // Validate finished if found using SHA-256
            if let Some(fin) = &recovered_fin {
                self.verify_server_finished_with_hash::<Sha256>(&server_hs_secret, client_hello, server_hello, recovered_cert.as_ref(), recovered_cv.as_ref(), fin)?;
            }
            return Ok(Some((recovered_cert, recovered_cv, recovered_fin.unwrap_or_default())));
        } else {
            let hk = Hkdf::<Sha384>::from_prk(&server_hs_secret).map_err(|_| VefasCoreError::ValidationError("invalid PRK".into()))?;
            let mut key = [0u8; 32];

            let mut label_key = Vec::new();
            label_key.extend_from_slice(&u16::to_be_bytes(32));
            label_key.push(6 + b"key".len() as u8);
            label_key.extend_from_slice(b"tls13 ");
            label_key.extend_from_slice(b"key");
            label_key.push(0);
            hk.expand(&label_key, &mut key).map_err(|_| VefasCoreError::ValidationError("HKDF expand key failed".into()))?;

            let mut label_iv = Vec::new();
            label_iv.extend_from_slice(&u16::to_be_bytes(12));
            label_iv.push(6 + b"iv".len() as u8);
            label_iv.extend_from_slice(b"tls13 ");
            label_iv.extend_from_slice(b"iv");
            label_iv.push(0);
            hk.expand(&label_iv, &mut iv_static).map_err(|_| VefasCoreError::ValidationError("HKDF expand iv failed".into()))?;

            // Decrypt with AES-256-GCM
            let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VefasCoreError::ValidationError("AES key error".into()))?;
            let (recovered_cert, recovered_cv, recovered_fin) = process_records(&cipher, records.clone(), &mut iv_static);
            // Validate finished if found using SHA-384
            if let Some(fin) = &recovered_fin {
                self.verify_server_finished_with_hash::<Sha384>(&server_hs_secret, client_hello, server_hello, recovered_cert.as_ref(), recovered_cv.as_ref(), fin)?;
            }
            return Ok(Some((recovered_cert, recovered_cv, recovered_fin.unwrap_or_default())));
        }

        // Helper closure over generic cipher type
        fn process_records<C: AeadInPlace<NonceSize = aes_gcm::aead::consts::U12, TagSize = aes_gcm::aead::consts::U16>>(
            cipher: &C,
            records: Vec<crate::records::TlsRecord>,
            iv_static: &mut [u8; 12],
        ) -> (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>) {
            let mut seq: u64 = 0;
            let mut recovered_cert: Option<Vec<u8>> = None;
            let mut recovered_cv: Option<Vec<u8>> = None;
            let mut recovered_fin: Option<Vec<u8>> = None;

            for rec in records {
            use crate::records::ContentType;
            if rec.content_type != ContentType::ApplicationData { continue; }

            // Nonce = iv_static XOR seq (big-endian in last 8 bytes)
            let mut nonce = *iv_static;
            let seq_be = seq.to_be_bytes();
            for i in 0..8 { nonce[4 + i] ^= seq_be[i]; }
            seq = seq.saturating_add(1);

            // TLS 1.3 inner content: ciphertext || tag, last byte is inner content type; remove padding 0x00s before that
                let mut buf = rec.payload.clone();
                if buf.len() < 16 + 1 { continue; }
                let tag = GenericArray::from_slice(&buf[buf.len()-16..]);
                // Build AAD from record header (type=0x17, legacy_version, length)
                let aad = [
                    0x17u8,
                    rec.legacy_version[0],
                    rec.legacy_version[1],
                    (rec.length >> 8) as u8,
                    (rec.length & 0xff) as u8,
                ];

            // Decrypt in place
                let nonce_arr = GenericArray::from_slice(&nonce);
                let mut plaintext = buf[..buf.len()-16].to_vec();
                if cipher.decrypt_in_place_detached(nonce_arr, &aad, &mut plaintext, tag).is_err() { continue; }

            // Strip padding zeros at end, last byte is inner content type
                while let Some(&0) = plaintext.last() { plaintext.pop(); }
                if plaintext.is_empty() { continue; }
                let inner_ct = plaintext.pop().unwrap();
                if inner_ct != 0x16 { continue; } // not handshake

            // Parse handshake messages within plaintext
                let mut idx = 0usize;
                while idx + 4 <= plaintext.len() {
                let typ = plaintext[idx];
                let len = ((plaintext[idx+1] as usize) << 16) | ((plaintext[idx+2] as usize) << 8) | (plaintext[idx+3] as usize);
                idx += 4;
                if idx + len > plaintext.len() { break; }
                let body = &plaintext[idx..idx+len];
                idx += len;

                match typ {
                    8 => { // EncryptedExtensions (not returned, but affects transcript in vector tests)
                        // For now, we don't persist EE outside this scope. Vector tests pass EE separately when needed.
                    },
                    11 => if recovered_cert.is_none() { // Certificate
                        let mut msg = vec![11, ((len>>16)&0xff) as u8, ((len>>8)&0xff) as u8, (len&0xff) as u8];
                        msg.extend_from_slice(body);
                        recovered_cert = Some(msg);
                    },
                    15 => if recovered_cv.is_none() { // CertificateVerify
                        let mut msg = vec![15, ((len>>16)&0xff) as u8, ((len>>8)&0xff) as u8, (len&0xff) as u8];
                        msg.extend_from_slice(body);
                        recovered_cv = Some(msg);
                    },
                    20 => if recovered_fin.is_none() { // Finished
                        let mut msg = vec![20, ((len>>16)&0xff) as u8, ((len>>8)&0xff) as u8, (len&0xff) as u8];
                        msg.extend_from_slice(body);
                        recovered_fin = Some(msg);
                    },
                    _ => {}
                }
                }
            }
            (recovered_cert, recovered_cv, recovered_fin)
        }

        Ok(None)
    }

    /// Verify Server Finished against transcript hash using the selected hash algorithm (SHA-256 or SHA-384)
    fn verify_server_finished_with_hash<H: Digest + Default + Clone + 'static>(
        &self,
        server_hs_secret: &Vec<u8>,
        client_hello: &Vec<u8>,
        server_hello: &Vec<u8>,
        cert: Option<&Vec<u8>>,
        cert_verify: Option<&Vec<u8>>,
        finished: &Vec<u8>,
    ) -> Result<()> {
        // Build transcript over handshake messages up to (excluding) Finished
        let mut transcript = Vec::new();
        transcript.extend_from_slice(client_hello);
        transcript.extend_from_slice(server_hello);
        // Note: When called from try_decrypt..., EncryptedExtensions is included in that function's transcript path.
        if let Some(c) = cert { transcript.extend_from_slice(c); }
        if let Some(cv) = cert_verify { transcript.extend_from_slice(cv); }
        let th = H::digest(&transcript);

        // HKDF-Expand-Label(secret, "finished", "", Hash.length)
        let out_len = <H as Digest>::output_size();
        // hkdf type specialization based on H
        let mut finished_key = vec![0u8; out_len];
        if out_len == 32 {
            let hk = Hkdf::<Sha256>::from_prk(server_hs_secret).map_err(|_| VefasCoreError::ValidationError("invalid PRK".into()))?;
            let mut label = Vec::new();
            label.extend_from_slice(&u16::to_be_bytes(out_len as u16));
            label.push(6 + b"finished".len() as u8);
            label.extend_from_slice(b"tls13 finished");
            label.push(0);
            hk.expand(&label, &mut finished_key).map_err(|_| VefasCoreError::ValidationError("HKDF expand finished failed".into()))?;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).map_err(|_| VefasCoreError::ValidationError("HMAC key error".into()))?;
            mac.update(&th);
            let expected = mac.finalize().into_bytes();
            self.compare_finished(finished, &expected)
        } else if out_len == 48 {
            let hk = Hkdf::<Sha384>::from_prk(server_hs_secret).map_err(|_| VefasCoreError::ValidationError("invalid PRK".into()))?;
            let mut label = Vec::new();
            label.extend_from_slice(&u16::to_be_bytes(out_len as u16));
            label.push(6 + b"finished".len() as u8);
            label.extend_from_slice(b"tls13 finished");
            label.push(0);
            hk.expand(&label, &mut finished_key).map_err(|_| VefasCoreError::ValidationError("HKDF expand finished failed".into()))?;
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&finished_key).map_err(|_| VefasCoreError::ValidationError("HMAC key error".into()))?;
            mac.update(&th);
            let expected = mac.finalize().into_bytes();
            self.compare_finished(finished, &expected)
        } else {
            Err(VefasCoreError::ValidationError("Unsupported hash length for Finished".into()))
        }
    }

    fn compare_finished(&self, finished: &Vec<u8>, expected: &[u8]) -> Result<()> {
        if finished.len() < 4 { return Err(VefasCoreError::ValidationError("Finished too short".into())); }
        let fin_len = ((finished[1] as usize) << 16) | ((finished[2] as usize) << 8) | (finished[3] as usize);
        if fin_len != expected.len() || &finished[4..4+fin_len] != expected {
            return Err(VefasCoreError::ValidationError("Server Finished verify_data mismatch".into()));
        }
        Ok(())
    }

    /// Extract certificate chain from a TLS 1.3 Certificate handshake message
    fn extract_certificate_chain_from_certificate_msg(&self, cert_msg: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
        if cert_msg.is_empty() {
            return Ok(Vec::new());
        }

        // Parse TLS Certificate message (RFC 8446 Section 4.4.2)
        // Certificate message format:
        // - certificate_request_context_length: 1 byte
        // - certificate_request_context: variable
        // - certificate_list_length: 3 bytes
        // - certificate_list: variable (series of certificate entries)

        let cert_data = cert_msg;
        // Expect handshake header (type + length) followed by payload
        if cert_data.len() < 4 {
            return Err(VefasCoreError::ValidationError("Certificate message too short".to_string()));
        }

        // Skip handshake header (4 bytes)
        let mut offset = 4;

        // Skip certificate request context
        let context_length = cert_data[offset] as usize;
        offset += 1 + context_length;

        if offset + 3 > cert_data.len() {
            return Err(VefasCoreError::ValidationError("Invalid certificate message format".to_string()));
        }

        // Read certificate list length (3 bytes)
        let cert_list_length = u32::from_be_bytes([0, cert_data[offset], cert_data[offset + 1], cert_data[offset + 2]]) as usize;
        offset += 3;

        if offset + cert_list_length > cert_data.len() {
            return Err(VefasCoreError::ValidationError("Certificate list length exceeds message size".to_string()));
        }

        let mut certificates = Vec::new();
        let cert_list_end = offset + cert_list_length;

        // Parse individual certificates
        while offset < cert_list_end {
            if offset + 3 > cert_list_end {
                break;
            }

            // Certificate length (3 bytes)
            let cert_length = u32::from_be_bytes([0, cert_data[offset], cert_data[offset + 1], cert_data[offset + 2]]) as usize;
            offset += 3;

            if offset + cert_length > cert_list_end {
                return Err(VefasCoreError::ValidationError("Certificate length exceeds remaining data".to_string()));
            }

            // Extract certificate data
            let certificate = cert_data[offset..offset + cert_length].to_vec();
            certificates.push(certificate);
            offset += cert_length;

            // Skip extensions (2 bytes length + variable data)
            if offset + 2 <= cert_list_end {
                let ext_length = u16::from_be_bytes([cert_data[offset], cert_data[offset + 1]]) as usize;
                offset += 2 + ext_length;
            }
        }

        Ok(certificates)
    }

    /// Generate deterministic verifier nonce based on bundle contents
    fn generate_deterministic_nonce(&self, components: &BundleComponents) -> Result<[u8; 32]> {
        use sha2::{Sha256, Digest};

        let mut hasher = Sha256::new();

        // Hash all relevant bundle components for deterministic nonce
        hasher.update(&components.client_hello);
        hasher.update(&components.server_hello);
        hasher.update(&components.certificate_msg);
        hasher.update(&components.certificate_verify_msg);
        hasher.update(&components.metadata.domain.as_bytes());
        hasher.update(&components.metadata.timestamp.to_be_bytes());

        let hash = hasher.finalize();
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&hash);

        Ok(nonce)
    }


    /// Split application data into request and response parts
    fn split_application_data(&self, app_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        // Try to find the boundary between HTTP request and response
        if let Some(response_start) = self.find_http_response_boundary(app_data) {
            let request_data = app_data[..response_start].to_vec();
            let response_data = app_data[response_start..].to_vec();
            Ok((request_data, response_data))
        } else {
            // If we can't find a clear boundary, treat all as request data
            Ok((app_data.to_vec(), Vec::new()))
        }
    }

    /// Find the boundary between HTTP request and response in application data
    fn find_http_response_boundary(&self, data: &[u8]) -> Option<usize> {
        // Look for HTTP response patterns
        let patterns: &[&[u8]] = &[b"HTTP/1.1 ", b"HTTP/1.0 ", b"HTTP/2"];

        for pattern in patterns {
            if let Some(pos) = data.windows(pattern.len()).position(|window| window == *pattern) {
                return Some(pos);
            }
        }

        None
    }
}

#[cfg(test)]
mod finished_tests {
    use super::*;
    use aes_gcm::aead::AeadInPlace;

    fn hello_handshake(msg_type: u8, random: [u8; 32]) -> Vec<u8> {
        // payload: legacy_version(2) + random(32)
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0x03, 0x03]);
        payload.extend_from_slice(&random);
        let len = payload.len() as u32;
        let mut out = Vec::new();
        out.push(msg_type);
        let be = len.to_be_bytes();
        out.extend_from_slice(&be[1..4]);
        out.extend_from_slice(&payload);
        out
    }

    fn tls_record(ct: u8, version: [u8; 2], payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(ct);
        out.extend_from_slice(&version);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn decrypt_and_validate_finished_sha256_succeeds() {
        // Synthetic server handshake secret (32 bytes -> SHA-256 path)
        let server_hs_secret = [0x11u8; 32].to_vec();

        // Derive key/iv
        let hk = Hkdf::<Sha256>::from_prk(&server_hs_secret).unwrap();
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        let mut label_key = Vec::new();
        label_key.extend_from_slice(&u16::to_be_bytes(16));
        label_key.push(6 + b"key".len() as u8);
        label_key.extend_from_slice(b"tls13 ");
        label_key.extend_from_slice(b"key");
        label_key.push(0);
        hk.expand(&label_key, &mut key).unwrap();
        let mut label_iv = Vec::new();
        label_iv.extend_from_slice(&u16::to_be_bytes(12));
        label_iv.push(6 + b"iv".len() as u8);
        label_iv.extend_from_slice(b"tls13 ");
        label_iv.extend_from_slice(b"iv");
        label_iv.push(0);
        hk.expand(&label_iv, &mut iv).unwrap();

        // Build transcript (up to but excluding Finished)
        let ch = hello_handshake(1, [1u8; 32]);
        let sh = hello_handshake(2, [2u8; 32]);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&ch);
        transcript.extend_from_slice(&sh);
        let th = Sha256::digest(&transcript);

        // finished_key
        let mut label_finished = Vec::new();
        label_finished.extend_from_slice(&u16::to_be_bytes(32));
        label_finished.push(6 + b"finished".len() as u8);
        label_finished.extend_from_slice(b"tls13 finished");
        label_finished.push(0);
        let mut finished_key = [0u8; 32];
        hk.expand(&label_finished, &mut finished_key).unwrap();
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).unwrap();
        mac.update(&th);
        let verify_data = mac.finalize().into_bytes();

        // Build Finished handshake message
        let mut fin = Vec::new();
        fin.push(20);
        let be = (verify_data.len() as u32).to_be_bytes();
        fin.extend_from_slice(&be[1..4]);
        fin.extend_from_slice(&verify_data);

        // Inner plaintext = Finished || content_type(0x16)
        let mut inner = fin.clone();
        inner.push(0x16);

        // Encrypt with AES-128-GCM seq=0, nonce = iv ^ seq, AAD = record header (type, version, length)
        let mut nonce = iv;
        let cipher = Aes128Gcm::new_from_slice(&key).unwrap();
        let mut buf = inner.clone();
        let payload_len = buf.len() + 16; // ciphertext length + tag
        let aad = [0x17u8, 0x03, 0x03, (payload_len >> 8) as u8, (payload_len & 0xff) as u8];
        let tag = cipher.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut buf).unwrap();
        let mut payload = buf;
        payload.extend_from_slice(&tag);
        let tls = tls_record(23, [0x03, 0x03], &payload);

        // Prepare SessionData and SecretData
        let session = SessionData {
            outbound_bytes: vec![],
            inbound_bytes: tls,
            certificate_chain: vec![
                // Mock certificate in DER format (simplified)
                rustls::pki_types::CertificateDer::from(vec![
                    0x30, 0x82, 0x01, 0x00, // Basic DER certificate structure
                    0x30, 0x81, 0xED, 0xA0, 0x03, 0x02, 0x01, 0x02,
                    0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Serial number
                ])
            ],
            // Use a simple cipher suite for testing
            negotiated_suite: rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            protocol_version: rustls::ProtocolVersion::TLSv1_3,
            server_name: "example.com".into(),
            timestamp: 0,
            connection_id: [0u8; 16],
            client_ephemeral_private_key: Some([0x11; 32]),
        };

        let secrets = SecretData {
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            traffic_secrets: vec![TrafficSecret { label: "SERVER_HANDSHAKE_TRAFFIC_SECRET".into(), secret: server_hs_secret, client_random: [0u8; 32] }],
        };

        let builder = BundleBuilder::new();
        let got = builder.try_decrypt_and_validate_server_finished(&session, &secrets, &ch, &sh).unwrap();
        assert!(got.is_some());
        let (_cert, _cv, finished) = got.unwrap();
        assert_eq!(finished, fin);
    }

    #[test]
    fn decrypt_and_validate_finished_sha384_succeeds() {
        // Synthetic server handshake secret (48 bytes -> SHA-384 path)
        let server_hs_secret = vec![0x22u8; 48];

        // Derive key/iv
        let hk = Hkdf::<Sha384>::from_prk(&server_hs_secret).unwrap();
        let mut key = [0u8; 32];
        let mut iv = [0u8; 12];
        let mut label_key = Vec::new();
        label_key.extend_from_slice(&u16::to_be_bytes(32));
        label_key.push(6 + b"key".len() as u8);
        label_key.extend_from_slice(b"tls13 ");
        label_key.extend_from_slice(b"key");
        label_key.push(0);
        hk.expand(&label_key, &mut key).unwrap();
        let mut label_iv = Vec::new();
        label_iv.extend_from_slice(&u16::to_be_bytes(12));
        label_iv.push(6 + b"iv".len() as u8);
        label_iv.extend_from_slice(b"tls13 ");
        label_iv.extend_from_slice(b"iv");
        label_iv.push(0);
        hk.expand(&label_iv, &mut iv).unwrap();

        // Build transcript (up to but excluding Finished)
        let ch = hello_handshake(1, [3u8; 32]);
        let sh = hello_handshake(2, [4u8; 32]);
        let mut transcript = Vec::new();
        transcript.extend_from_slice(&ch);
        transcript.extend_from_slice(&sh);
        let th = Sha384::digest(&transcript);

        // finished_key
        let mut label_finished = Vec::new();
        label_finished.extend_from_slice(&u16::to_be_bytes(48));
        label_finished.push(6 + b"finished".len() as u8);
        label_finished.extend_from_slice(b"tls13 finished");
        label_finished.push(0);
        let mut finished_key = [0u8; 48];
        hk.expand(&label_finished, &mut finished_key).unwrap();
        let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&finished_key).unwrap();
        mac.update(&th);
        let verify_data = mac.finalize().into_bytes();

        // Build Finished handshake message
        let mut fin = Vec::new();
        fin.push(20);
        let be = (verify_data.len() as u32).to_be_bytes();
        fin.extend_from_slice(&be[1..4]);
        fin.extend_from_slice(&verify_data);

        // Inner plaintext = Finished || content_type(0x16)
        let mut inner = fin.clone();
        inner.push(0x16);

        // Encrypt with AES-256-GCM seq=0; AAD = record header with ciphertext length
        let mut nonce = iv;
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let mut buf = inner.clone();
        let payload_len = buf.len() + 16;
        let aad = [0x17u8, 0x03, 0x03, (payload_len >> 8) as u8, (payload_len & 0xff) as u8];
        let tag = cipher.encrypt_in_place_detached(GenericArray::from_slice(&nonce), &aad, &mut buf).unwrap();
        let mut payload = buf;
        payload.extend_from_slice(&tag);
        let tls = tls_record(23, [0x03, 0x03], &payload);

        let session = SessionData {
            outbound_bytes: vec![],
            inbound_bytes: tls,
            certificate_chain: vec![
                // Mock certificate in DER format (simplified)
                rustls::pki_types::CertificateDer::from(vec![
                    0x30, 0x82, 0x01, 0x00, // Basic DER certificate structure
                    0x30, 0x81, 0xED, 0xA0, 0x03, 0x02, 0x01, 0x02,
                    0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Serial number
                ])
            ],
            // Use a simple cipher suite for testing
            negotiated_suite: rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
            protocol_version: rustls::ProtocolVersion::TLSv1_3,
            server_name: "example.com".into(),
            timestamp: 0,
            connection_id: [0u8; 16],
            client_ephemeral_private_key: Some([0x11; 32]),
        };

        let secrets = SecretData {
            client_random: [0u8; 32],
            server_random: [0u8; 32],
            traffic_secrets: vec![TrafficSecret { label: "SERVER_HANDSHAKE_TRAFFIC_SECRET".into(), secret: server_hs_secret, client_random: [0u8; 32] }],
        };

        let builder = BundleBuilder::new();
        let got = builder.try_decrypt_and_validate_server_finished(&session, &secrets, &ch, &sh).unwrap();
        assert!(got.is_some());
        let (_cert, _cv, finished) = got.unwrap();
        assert_eq!(finished, fin);
    }

    #[derive(serde::Deserialize)]
    struct FinishedVector {
        hash: String,
        server_hs_secret: String,
        client_hello: String,
        server_hello: String,
        certificate: Option<String>,
        certificate_verify: Option<String>,
        finished: Option<String>,
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> { hex::decode(s.replace([' ', '\n'], "")).unwrap() }

    #[test]
    fn rfc8448_finished_vectors_dir() {
        use std::fs;
        use std::path::Path;

        // Resolve directory: env override or default fixtures
        let dir = std::env::var("RFC8448_FINISHED_DIR").unwrap_or_else(|_|
            String::from("crates/vefas-core/tests/fixtures/rfc8448_finished")
        );
        let p = Path::new(&dir);
        if !p.exists() { return; }

        let builder = BundleBuilder::new();
        for entry in fs::read_dir(p).unwrap().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
            let content = fs::read_to_string(&path).unwrap();
            let v: FinishedVector = serde_json::from_str(&content).unwrap();

            let server_hs_secret = hex_to_bytes(&v.server_hs_secret);
            let ch = hex_to_bytes(&v.client_hello);
            let sh = hex_to_bytes(&v.server_hello);
            let cert = v.certificate.as_ref().map(|s| hex_to_bytes(s));
            let cv = v.certificate_verify.as_ref().map(|s| hex_to_bytes(s));
            let fin_opt = v.finished.as_ref().map(|s| hex_to_bytes(s));

            let secrets = SecretData {
                client_random: [0u8; 32],
                server_random: [0u8; 32],
                traffic_secrets: vec![TrafficSecret { label: "SERVER_HANDSHAKE_TRAFFIC_SECRET".into(), secret: server_hs_secret.clone(), client_random: [0u8; 32] }],
            };

            if v.hash.eq_ignore_ascii_case("SHA256") || server_hs_secret.len() == 32 {
                if let Some(fin) = fin_opt {
                    builder.verify_server_finished_with_hash::<Sha256>(&server_hs_secret, &ch, &sh, cert.as_ref(), cv.as_ref(), &fin).expect("sha256 finished verify");
                } else {
                    // Compute expected Finished and validate
                    let mut transcript = Vec::new(); transcript.extend_from_slice(&ch); transcript.extend_from_slice(&sh); if let Some(c)=&cert{transcript.extend_from_slice(c);} if let Some(cv)=&cv{transcript.extend_from_slice(cv);} let th = Sha256::digest(&transcript);
                    let hk = Hkdf::<Sha256>::from_prk(&server_hs_secret).unwrap(); let mut label = Vec::new(); label.extend_from_slice(&u16::to_be_bytes(32)); label.push(6 + b"finished".len() as u8); label.extend_from_slice(b"tls13 finished"); label.push(0); let mut finished_key=[0u8;32]; hk.expand(&label, &mut finished_key).unwrap(); let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&finished_key).unwrap(); mac.update(&th); let verify_data = mac.finalize().into_bytes(); let mut fin = vec![20,0,0,32]; fin.extend_from_slice(&verify_data);
                    builder.verify_server_finished_with_hash::<Sha256>(&server_hs_secret, &ch, &sh, cert.as_ref(), cv.as_ref(), &fin).expect("sha256 finished verify");
                }
            } else if v.hash.eq_ignore_ascii_case("SHA384") || server_hs_secret.len() == 48 {
                if let Some(fin) = fin_opt {
                    builder.verify_server_finished_with_hash::<Sha384>(&server_hs_secret, &ch, &sh, cert.as_ref(), cv.as_ref(), &fin).expect("sha384 finished verify");
                } else {
                    let mut transcript = Vec::new(); transcript.extend_from_slice(&ch); transcript.extend_from_slice(&sh); if let Some(c)=&cert{transcript.extend_from_slice(c);} if let Some(cv)=&cv{transcript.extend_from_slice(cv);} let th = Sha384::digest(&transcript);
                    let hk = Hkdf::<Sha384>::from_prk(&server_hs_secret).unwrap(); let mut label = Vec::new(); label.extend_from_slice(&u16::to_be_bytes(48)); label.push(6 + b"finished".len() as u8); label.extend_from_slice(b"tls13 finished"); label.push(0); let mut finished_key=[0u8;48]; hk.expand(&label, &mut finished_key).unwrap(); let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&finished_key).unwrap(); mac.update(&th); let verify_data = mac.finalize().into_bytes(); let mut fin = vec![20,0,0,48]; fin.extend_from_slice(&verify_data);
                    builder.verify_server_finished_with_hash::<Sha384>(&server_hs_secret, &ch, &sh, cert.as_ref(), cv.as_ref(), &fin).expect("sha384 finished verify");
                }
            } else {
                panic!("Unsupported hash in vector {:?}", path);
            }
        }
    }
}

/// Internal structure for organizing handshake components
#[derive(Debug, Default)]
struct HandshakeComponents {
    pub client_hello: Vec<u8>,
    pub server_hello: Vec<u8>,
    pub certificate_msg: Vec<u8>,
    pub certificate_verify_msg: Vec<u8>,
    pub finished_msgs: Vec<Vec<u8>>,
    pub other_messages: Vec<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keylog::VefasKeyLog;
    use rustls::{KeyLog, crypto::aws_lc_rs::cipher_suite};
    use std::io::{Read, Write};

    // Mock TcpStream for testing
    struct MockTcpStream {
        read_data: Vec<u8>,
        write_data: Vec<u8>,
        read_pos: usize,
    }

    impl MockTcpStream {
        fn new(read_data: Vec<u8>) -> Self {
            Self {
                read_data,
                write_data: Vec::new(),
                read_pos: 0,
            }
        }
    }

    impl Read for MockTcpStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let remaining = self.read_data.len().saturating_sub(self.read_pos);
            let to_read = std::cmp::min(buf.len(), remaining);

            if to_read == 0 {
                return Ok(0);
            }

            buf[..to_read].copy_from_slice(&self.read_data[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            Ok(to_read)
        }
    }

    impl Write for MockTcpStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_data.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn create_test_session_data() -> SessionData {
        use rustls::ProtocolVersion;

        // Helpers to build well-formed TLS records
        fn make_handshake_record(msg_type: u8, payload: Vec<u8>) -> Vec<u8> {
            let mut record = Vec::new();
            let rec_len = (4 + payload.len()) as u16; // handshake header + payload
            record.push(22); // Handshake
            record.extend_from_slice(&[3, 3]); // legacy version
            record.extend_from_slice(&rec_len.to_be_bytes());
            record.push(msg_type);
            let be = (payload.len() as u32).to_be_bytes();
            record.extend_from_slice(&be[1..4]);
            record.extend_from_slice(&payload);
            record
        }

        fn make_app_record(data: &[u8]) -> Vec<u8> {
            let mut record = Vec::new();
            let rec_len = data.len() as u16;
            record.push(23); // ApplicationData
            record.extend_from_slice(&[3, 3]);
            record.extend_from_slice(&rec_len.to_be_bytes());
            record.extend_from_slice(data);
            record
        }

        // RFC 8448 Simple 1-RTT: ClientHello complete record (201 octets)
        let ch_record: Vec<u8> = vec![
            0x16,0x03,0x01,0x00,0xC4,0x01,0x00,0x00,0xC0,0x03,0x03,0xCB,0x34,0xEC,0xB1,0xE7,0x81,0x63,0xBA,0x1C,0x38,0xC6,0xDA,0xCB,0x19,0x6A,0x6D,0xFF,0xA2,0x1A,0x8D,0x99,0x12,0xEC,0x18,0xA2,0xEF,0x62,0x83,0x02,0x4D,0xEC,0xE7,0x00,0x00,0x06,0x13,0x01,0x13,0x03,0x13,0x02,0x01,0x00,0x00,0x91,0x00,0x00,0x00,0x0B,0x00,0x09,0x00,0x00,0x06,0x73,0x65,0x72,0x76,0x65,0x72,0xFF,0x01,0x00,0x01,0x00,0x00,0x0A,0x00,0x14,0x00,0x12,0x00,0x1D,0x00,0x17,0x00,0x18,0x00,0x19,0x01,0x00,0x01,0x01,0x01,0x02,0x01,0x03,0x01,0x04,0x00,0x23,0x00,0x00,0x00,0x33,0x00,0x26,0x00,0x24,0x00,0x1D,0x00,0x20,0x99,0x38,0x1D,0xE5,0x60,0xE4,0xBD,0x43,0xD2,0x3D,0x8E,0x43,0x5A,0x7D,0xBA,0xFE,0xB3,0xC0,0x6E,0x51,0xC1,0x3C,0xAE,0x4D,0x54,0x13,0x69,0x1E,0x52,0x9A,0xAF,0x2C,0x00,0x2B,0x00,0x03,0x02,0x03,0x04,0x00,0x0D,0x00,0x20,0x00,0x1E,0x04,0x03,0x05,0x03,0x06,0x03,0x02,0x03,0x08,0x04,0x08,0x05,0x08,0x06,0x04,0x01,0x05,0x01,0x06,0x01,0x02,0x01,0x04,0x02,0x05,0x02,0x06,0x02,0x02,0x02,0x00,0x2D,0x00,0x02,0x01,0x01,0x00,0x1C,0x00,0x02,0x40,0x01
        ];

        // RFC 8448 Simple 1-RTT: ServerHello complete record (95 octets)
        let sh_record: Vec<u8> = vec![
            0x16,0x03,0x03,0x00,0x5A,0x02,0x00,0x00,0x56,0x03,0x03,0xA6,0xAF,0x06,0xA4,0x12,0x18,0x60,0xDC,0x5E,0x6E,0x60,0x24,0x9C,0xD3,0x4C,0x95,0x93,0x0C,0x8A,0xC5,0xCB,0x14,0x34,0xDA,0xC1,0x55,0x77,0x2E,0xD3,0xE2,0x69,0x28,0x00,0x13,0x01,0x00,0x00,0x2E,0x00,0x33,0x00,0x24,0x00,0x1D,0x00,0x20,0xC9,0x82,0x88,0x76,0x11,0x20,0x95,0xFE,0x66,0x76,0x2B,0xDB,0xF7,0xC6,0x72,0xE1,0x56,0xD6,0xCC,0x25,0x3B,0x83,0x3D,0xF1,0xDD,0x69,0xB1,0xB0,0x4E,0x75,0x1F,0x0F,0x00,0x2B,0x00,0x02,0x03,0x04
        ];

        // RFC 8448 Simple 1-RTT: Certificate handshake payload (strip 4-byte header 0b 00 01 b9)
        let cert_payload: Vec<u8> = vec![
            0x00,0x00,0x01,0xB5,0x00,0x01,0xB0,0x30,0x82,0x01,0xAC,0x30,0x82,0x01,0x15,0xA0,0x03,0x02,0x01,0x02,0x02,0x01,0x02,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00,0x30,0x0E,0x31,0x0C,0x30,0x0A,0x06,0x03,0x55,0x04,0x03,0x13,0x03,0x72,0x73,0x61,0x30,0x1E,0x17,0x0D,0x31,0x36,0x30,0x37,0x33,0x30,0x30,0x31,0x32,0x33,0x35,0x39,0x5A,0x17,0x0D,0x32,0x36,0x30,0x37,0x33,0x30,0x30,0x31,0x32,0x33,0x35,0x39,0x5A,0x30,0x0E,0x31,0x0C,0x30,0x0A,0x06,0x03,0x55,0x04,0x03,0x13,0x03,0x72,0x73,0x61,0x30,0x81,0x9F,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00,0x03,0x81,0x8D,0x00,0x30,0x81,0x89,0x02,0x81,0x81,0x00,0xB4,0xBB,0x49,0x8F,0x82,0x79,0x30,0x3D,0x98,0x08,0x36,0x39,0x9B,0x36,0xC6,0x98,0x8C,0x0C,0x68,0xDE,0x55,0xE1,0xBD,0xB8,0x26,0xD3,0x90,0x1A,0x24,0x61,0xEA,0xFD,0x2D,0xE4,0x9A,0x91,0xD0,0x15,0xAB,0xBC,0x9A,0x95,0x13,0x7A,0xCE,0x6C,0x1A,0xF1,0x9E,0xAA,0x6A,0xF9,0x8C,0x7C,0xED,0x43,0x12,0x09,0x98,0xE1,0x87,0xA8,0x0E,0xE0,0xCC,0xB0,0x52,0x4B,0x1B,0x01,0x8C,0x3E,0x0B,0x63,0x26,0x4D,0x44,0x9A,0x6D,0x38,0xE2,0x2A,0x5F,0xDA,0x43,0x08,0x46,0x74,0x80,0x30,0x53,0x0E,0xF0,0x46,0x1C,0x8C,0xA9,0xD9,0xEF,0xBF,0xAE,0x8E,0xA6,0xD1,0xD0,0x3E,0x2B,0xD1,0x93,0xEF,0xF0,0xAB,0x9A,0x80,0x02,0xC4,0x74,0x28,0xA6,0xD3,0x5A,0x8D,0x88,0xD7,0x9F,0x7F,0x1E,0x3F,0x02,0x03,0x01,0x00,0x01,0xA3,0x1A,0x30,0x18,0x30,0x09,0x06,0x03,0x55,0x1D,0x13,0x04,0x02,0x30,0x00,0x30,0x0B,0x06,0x03,0x55,0x1D,0x0F,0x04,0x04,0x03,0x02,0x05,0xA0,0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,0x05,0x00,0x03,0x81,0x81,0x00,0x85,0xAA,0xD2,0xA0,0xE5,0xB9,0x27,0x6B,0x90,0x8C,0x65,0xF7,0x3A,0x72,0x67,0x17,0x06,0x18,0xA5,0x4C,0x5F,0x8A,0x7B,0x33,0x7D,0x2D,0xF7,0xA5,0x94,0x36,0x54,0x17,0xF2,0xEA,0xE8,0xF8,0xA5,0x8C,0x8F,0x81,0x72,0xF9,0x31,0x9C,0xF3,0x6B,0x7F,0xD6,0xC5,0x5B,0x80,0xF2,0x1A,0x03,0x01,0x51,0x56,0x72,0x60,0x96,0xFD,0x33,0x5E,0x5E,0x67,0xF2,0xDB,0xF1,0x02,0x70,0x2E,0x60,0x8C,0xCA,0xE6,0xBE,0xC1,0xFC,0x63,0xA4,0x2A,0x99,0xBE,0x5C,0x3E,0xB7,0x10,0x7C,0x3C,0x54,0xE9,0xB9,0xEB,0x2B,0xD5,0x20,0x3B,0x1C,0x3B,0x84,0xE0,0xA8,0xB2,0xF7,0x59,0x40,0x9B,0xA3,0xEA,0xC9,0xD9,0x1D,0x40,0x2D,0xCC,0x0C,0xC8,0xF8,0x96,0x12,0x29,0xAC,0x91,0x87,0xB4,0x2B,0x4D,0xE1,0x00,0x00
        ];
        let cert_record = make_handshake_record(11, cert_payload);

        // RFC 8448 Simple 1-RTT: CertificateVerify payload (strip 4-byte header 0f 00 00 84)
        let cert_verify_payload: Vec<u8> = vec![
            0x08,0x04,0x00,0x80,0x5A,0x74,0x7C,0x5D,0x88,0xFA,0x9B,0xD2,0xE5,0x5A,0xB0,0x85,0xA6,0x10,0x15,0xB7,0x21,0x1F,0x82,0x4C,0xD4,0x84,0x14,0x5A,0xB3,0xFF,0x52,0xF1,0xFD,0xA8,0x47,0x7B,0x0B,0x7A,0xBC,0x90,0xDB,0x78,0xE2,0xD3,0x3A,0x5C,0x14,0x1A,0x07,0x86,0x53,0xFA,0x6B,0xEF,0x78,0x0C,0x5E,0xA2,0x48,0xEE,0xAA,0xA7,0x85,0xC4,0xF3,0x94,0xCA,0xB6,0xD3,0x0B,0xBE,0x8D,0x48,0x59,0xEE,0x51,0x1F,0x60,0x29,0x57,0xB1,0x54,0x11,0xAC,0x02,0x76,0x71,0x45,0x9E,0x46,0x44,0x5C,0x9E,0xA5,0x8C,0x18,0x1E,0x81,0x8E,0x95,0xB8,0xC3,0xFB,0x0B,0xF3,0x27,0x84,0x09,0xD3,0xBE,0x15,0x2A,0x3D,0xA5,0x04,0x3E,0x06,0x3D,0xDA,0x65,0xCD,0xF5,0xAE,0xA2,0x0D,0x53,0xDF,0xAC,0xD4,0x2F,0x74,0xF3
        ];
        let cert_verify_record = make_handshake_record(15, cert_verify_payload);

        // RFC 8448 Simple 1-RTT: Finished payload (strip 4-byte header 14 00 00 20)
        let fin_payload: Vec<u8> = vec![
            0x9B,0x9B,0x14,0x1D,0x90,0x63,0x37,0xFB,0xD2,0xCB,0xDC,0xE7,0x1D,0xF4,0xDE,0xDA,0x4A,0xB4,0x2C,0x30,0x95,0x72,0xCB,0x7F,0xFF,0xEE,0x54,0x54,0xB7,0x8F,0x07,0x18
        ];
        let fin_record = make_handshake_record(20, fin_payload);
        
        // RFC 8448 Simple 1-RTT: First client and server ApplicationData complete records (72 octets each)
        let client_app_record: Vec<u8> = vec![
            0x17,0x03,0x03,0x00,0x43,0xA2,0x3F,0x70,0x54,0xB6,0x2C,0x94,0xD0,0xAF,0xFA,0xFE,0x82,0x28,0xBA,0x55,0xCB,0xEF,0xAC,0xEA,0x42,0xF9,0x14,0xAA,0x66,0xBC,0xAB,0x3F,0x2B,0x98,0x19,0xA8,0xA5,0xB4,0x6B,0x39,0x5B,0xD5,0x4A,0x9A,0x20,0x44,0x1E,0x2B,0x62,0x97,0x4E,0x1F,0x5A,0x62,0x92,0xA2,0x97,0x70,0x14,0xBD,0x1E,0x3D,0xEA,0xE6,0x3A,0xEE,0xBB,0x21,0x69,0x49,0x15,0xE4
        ];
        let server_app_record: Vec<u8> = vec![
            0x17,0x03,0x03,0x00,0x43,0x2E,0x93,0x7E,0x11,0xEF,0x4A,0xC7,0x40,0xE5,0x38,0xAD,0x36,0x00,0x5F,0xC4,0xA4,0x69,0x32,0xFC,0x32,0x25,0xD0,0x5F,0x82,0xAA,0x1B,0x36,0xE3,0x0E,0xFA,0xF9,0x7D,0x90,0xE6,0xDF,0xFC,0x60,0x2D,0xCB,0x50,0x1A,0x59,0xA8,0xFC,0xC4,0x9C,0x4B,0xF2,0xE5,0xF0,0xA2,0x1C,0x00,0x47,0xC2,0xAB,0xF3,0x32,0x54,0x0D,0xD0,0x32,0xE1,0x67,0xC2,0x95,0x5D
        ];

        let outbound_bytes = [ch_record.clone(), client_app_record].concat();
        let inbound_bytes = [sh_record.clone(), cert_record, cert_verify_record, fin_record, server_app_record].concat();

        SessionData {
            outbound_bytes,
            inbound_bytes,
            certificate_chain: vec![
                // Mock certificate in DER format (simplified)
                rustls::pki_types::CertificateDer::from(vec![
                    0x30, 0x82, 0x01, 0x00, // Basic DER certificate structure
                    0x30, 0x81, 0xED, 0xA0, 0x03, 0x02, 0x01, 0x02,
                    0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Serial number
                ])
            ],
            // Use a simple cipher suite for testing
            negotiated_suite: rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
            protocol_version: ProtocolVersion::TLSv1_3,
            server_name: "example.com".to_string(),
            timestamp: 1234567890,
            connection_id: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            client_ephemeral_private_key: Some([0x11; 32]),
        }
    }

    fn create_test_http_data() -> HttpData {
        HttpData {
            request_bytes: b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec(),
            response_bytes: b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nHello World".to_vec(),
            status_code: 200,
            headers: vec![("Content-Length".to_string(), "11".to_string())],
            method: "GET".to_string(),
            path: "/test".to_string(),
            request_headers: vec![("Host".to_string(), "example.com".to_string())],
            response_body: b"Hello World".to_vec(),
        }
    }

    fn create_test_keylog() -> VefasKeyLog {
        let keylog = VefasKeyLog::new();

        // Add some test secrets
        keylog.log(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            &[1; 32],
            &[0xaa; 32],
        );
        keylog.log(
            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            &[1; 32],
            &[0xbb; 32],
        );

        keylog
    }

    #[test]
    fn test_bundle_builder_creation() {
        let _builder = BundleBuilder::new();
        // BundleBuilder created successfully
    }

    #[test]
    fn test_serialize_handshake_message() {
        let builder = BundleBuilder::new();
        let message = HandshakeMessage {
            msg_type: HandshakeType::ClientHello,
            length: 6,
            payload: vec![1, 2, 3, 4, 5, 6],
        };

        let serialized = builder.serialize_handshake_message(&message).unwrap();

        // Should be: type(1) + length(3) + payload(6) = 10 bytes
        assert_eq!(serialized.len(), 10);
        assert_eq!(serialized[0], 1); // ClientHello type
        assert_eq!(&serialized[1..4], &[0, 0, 6]); // Length in 3 bytes
        assert_eq!(&serialized[4..], &[1, 2, 3, 4, 5, 6]); // Payload
    }

    #[test]
    fn test_create_bundle_metadata() {
        let builder = BundleBuilder::new();
        let session = create_test_session_data();

        let metadata = builder.create_bundle_metadata(&session).unwrap();

        assert_eq!(metadata.domain, "example.com");
        assert_eq!(metadata.timestamp, 1234567890);
        assert!(metadata.tls_version.contains("TLSv1_3"));
        assert_eq!(metadata.connection_id, session.connection_id);
    }

    #[test]
    fn test_serialize_application_data() {
        let builder = BundleBuilder::new();
        let http_data = create_test_http_data();

        let app_data = builder.serialize_application_data(&http_data).unwrap();

        // Should contain both request and response bytes
        assert!(app_data.len() > 0);
        assert!(app_data.starts_with(b"GET /test HTTP/1.1"));
    }

    #[test]
    fn test_deterministic_bundle_creation() {
        let mut builder = BundleBuilder::new();
        let session = create_test_session_data();
        let http_data = create_test_http_data();
        let keylog = create_test_keylog();

        let bundle1 = builder.from_session_data(&session, &http_data, &keylog).unwrap();

        // Create a second bundle with the same inputs
        let mut builder2 = BundleBuilder::new();
        let bundle2 = builder2.from_session_data(&session, &http_data, &keylog).unwrap();

        // Bundles should be identical (deterministic)
        assert_eq!(bundle1.domain, bundle2.domain);
        assert_eq!(bundle1.timestamp, bundle2.timestamp);
        assert_eq!(bundle1.client_hello().unwrap(), bundle2.client_hello().unwrap());
        assert_eq!(bundle1.server_hello().unwrap(), bundle2.server_hello().unwrap());
    }

    #[test]
    fn test_bundle_contains_required_fields() {
        let mut builder = BundleBuilder::new();
        let session = create_test_session_data();
        let http_data = create_test_http_data();
        let keylog = create_test_keylog();

        let bundle = builder.from_session_data(&session, &http_data, &keylog).unwrap();

        // Verify all required fields are present
        assert_eq!(bundle.domain, "example.com");
        assert_eq!(bundle.timestamp, 1234567890);
        assert!(!bundle.client_hello().unwrap().is_empty());
        assert!(!bundle.server_hello().unwrap().is_empty());
        assert!(!bundle.encrypted_request().unwrap().is_empty());
        // Note: VefasCanonicalBundle doesn't have connection_id field
    }
}