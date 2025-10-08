//! TLS protocol parsing utilities for VEFAS
//!
//! This module provides comprehensive TLS 1.3 message parsing capabilities
//! that can be shared across different zkVM platforms. All parsing operations
//! include rigorous bounds checking and validation to ensure secure operation
//! in zero-knowledge contexts.
//!
//! This implementation leverages the rusticata tls-parser crate for robust
//! TLS message parsing while maintaining VEFAS-specific cryptographic operations.

use alloc::{format, vec::Vec};
use tls_parser::{
    parse_tls_plaintext, parse_tls_extensions, TlsMessage, TlsMessageHandshake, TlsPlaintext, 
    TlsRecordType, TlsVersion, TlsExtension,
};

#[cfg(feature = "std")]
extern crate std;

use crate::traits::VefasCrypto;
use vefas_types::{tls::CipherSuite, VefasError, VefasResult};

// Debug macro - disabled for now
#[cfg(feature = "std")]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        std::println!($($arg)*);
    };
}

#[cfg(not(feature = "std"))]
macro_rules! debug_print {
    ($($arg:tt)*) => {
        // No-op - debug logging disabled in no_std mode
    };
}

/// Parsed TLS handshake message
#[derive(Debug, Clone)]
pub struct HandshakeMessage<'a> {
    pub msg_type: u8,
    pub length: usize,
    pub body: &'a [u8],
}

/// Parsed TLS record
#[derive(Debug, Clone)]
pub struct TlsRecord<'a> {
    pub content_type: u8,
    pub version: u16,
    pub payload: &'a [u8],
}

/// Parsed ServerHello key_share extension
#[derive(Debug, Clone)]
pub struct KeyShare {
    pub group: u16,
    pub key_exchange: Vec<u8>,
}

/// Parse TLS handshake header using tls-parser crate
///
/// Returns (handshake_type, length, body) or None if malformed
/// Handles both raw handshake messages and handshake messages inside TLS records
pub fn parse_handshake_header(msg: &[u8]) -> Option<(u8, usize, &[u8])> {
    // Input validation
    if msg.is_empty() {
        return None;
    }

    // Maximum message size check (prevent DoS)
    if msg.len() > 65536 {
        return None;
    }

    // Try parsing as raw handshake first (type, len(3), body)
    if msg.len() >= 4 {
        let msg_type = msg[0];
        let msg_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        
        // Validate handshake type (TLS 1.3 handshake types)
        match msg_type {
            0x01 => {}, // ClientHello
            0x02 => {}, // ServerHello
            0x0b => {}, // Certificate
            0x0f => {}, // CertificateVerify
            0x14 => {}, // Finished
            _ => return None, // Invalid handshake type
        }
        
        if msg.len() >= 4 + msg_len {
            return Some((msg_type, msg_len, &msg[4..4 + msg_len]));
        }
    }

    // Try parsing as TLS record containing handshake
    if let Ok((remaining, record)) = parse_tls_plaintext(msg) {
        if remaining.is_empty() && record.hdr.record_type == TlsRecordType::Handshake {
            for message in record.msg {
                if let TlsMessage::Handshake(handshake) = message {
                    match handshake {
                        TlsMessageHandshake::ClientHello(_) => {
                            return Some((0x01, msg.len() - 4, &msg[4..]));
                        }
                        TlsMessageHandshake::ServerHello(_) => {
                            return Some((0x02, msg.len() - 4, &msg[4..]));
                        }
                        TlsMessageHandshake::Certificate(_) => {
                            return Some((0x0b, msg.len() - 4, &msg[4..]));
                        }
                        TlsMessageHandshake::CertificateVerify(_) => {
                            return Some((0x0f, msg.len() - 4, &msg[4..]));
                        }
                        TlsMessageHandshake::Finished(_) => {
                            return Some((0x14, msg.len() - 4, &msg[4..]));
                        }
                        _ => continue,
                    }
                }
            }
        }
    }

    None
}

/// Parse multiple concatenated TLS records from a byte stream using tls-parser
///
/// Returns a vector of parsed TLS records with their metadata
pub fn parse_tls_records(data: &[u8]) -> VefasResult<Vec<TlsPlaintext<'_>>> {
    let mut records = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() {
        // Use tls-parser to parse each record
        match parse_tls_plaintext(&data[offset..]) {
            Ok((remaining, record)) => {
                // Validate record type
                if record.hdr.record_type != TlsRecordType::ApplicationData {
                    return Err(VefasError::invalid_input(
                        "tls_records",
                        &format!("Expected ApplicationData, got {:?}", record.hdr.record_type),
                    ));
                }
                
                // Validate TLS version
                if record.hdr.version != TlsVersion(0x0303) {
                    return Err(VefasError::invalid_input(
                        "tls_records",
                        &format!("Expected TLS 1.2 version, got {:?}", record.hdr.version),
                    ));
                }
                
                records.push(record);
                
                // Calculate how much data was consumed
                let consumed = data.len() - remaining.len() - offset;
                offset += consumed;
            }
            Err(_) => {
                return Err(VefasError::invalid_input(
                    "tls_records",
                    &format!("Failed to parse TLS record at offset {}", offset),
                ));
            }
        }
    }
    
    Ok(records)
}

/// Parse cipher suite from ServerHello using tls-parser
pub fn parse_server_cipher_suite(server_hello: &[u8]) -> VefasResult<u16> {
    debug_print!("DEBUG parse_server_cipher_suite: ServerHello length: {}", server_hello.len());
    debug_print!("DEBUG parse_server_cipher_suite: ServerHello first 20 bytes: {:02x?}", &server_hello[..20.min(server_hello.len())]);
    
    // Try parsing as TLS record containing ServerHello first (most common case)
    debug_print!("DEBUG parse_server_cipher_suite: Trying TLS record parsing");
    if let Ok((_, record)) = parse_tls_plaintext(server_hello) {
        debug_print!("DEBUG parse_server_cipher_suite: TLS record parsed successfully");
        // Extract the ServerHello message
        for msg in record.msg {
            if let TlsMessage::Handshake(TlsMessageHandshake::ServerHello(hello)) = msg {
                debug_print!("DEBUG parse_server_cipher_suite: Found ServerHello in TLS record, cipher: 0x{:04x}", hello.cipher.0);
                // Validate cipher suite is supported
                match hello.cipher.0 {
                    0x1301 | 0x1302 | 0x1303 => {
                        debug_print!("DEBUG parse_server_cipher_suite: Supported TLS 1.3 cipher suite: 0x{:04x}", hello.cipher.0);
                        return Ok(hello.cipher.0);
                    }
                    _ => {
                        debug_print!("DEBUG parse_server_cipher_suite: Unsupported cipher suite: 0x{:04x}", hello.cipher.0);
                        return Err(VefasError::invalid_input(
                            "server_hello",
                            &format!("Unsupported cipher suite: 0x{:04x}", hello.cipher.0),
                        ));
                    }
                }
            }
        }
    }

    // Fallback: Try parsing as raw handshake data (for cases where it's not wrapped in a TLS record)
    debug_print!("DEBUG parse_server_cipher_suite: TLS record parsing failed, trying raw handshake parsing");
    if server_hello.len() >= 4 {
        let msg_type = server_hello[0];
        debug_print!("DEBUG parse_server_cipher_suite: Message type: 0x{:02x}", msg_type);
        
        if msg_type == 0x02 { // ServerHello
            let msg_len = ((server_hello[1] as usize) << 16) | ((server_hello[2] as usize) << 8) | (server_hello[3] as usize);
            debug_print!("DEBUG parse_server_cipher_suite: Message length: {}", msg_len);
            
            if server_hello.len() >= 4 + msg_len && msg_len >= 38 {
                // Parse ServerHello body: legacy_version(2) + random(32) + session_id_length(1) + cipher_suite(2) + compression_method(1)
                let body = &server_hello[4..4 + msg_len];
                debug_print!("DEBUG parse_server_cipher_suite: Body length: {}", body.len());
                debug_print!("DEBUG parse_server_cipher_suite: Body first 40 bytes: {:02x?}", &body[..40.min(body.len())]);
                
                if body.len() >= 38 {
                    // Parse ServerHello body properly:
                    // legacy_version(2) + random(32) + session_id_length(1) + session_id + cipher_suite(2) + compression_method(1)
                    let legacy_version = &body[0..2];
                    let random = &body[2..34];
                    let session_id_length = body[34] as usize;
                    debug_print!("DEBUG parse_server_cipher_suite: legacy_version: {:02x?}", legacy_version);
                    debug_print!("DEBUG parse_server_cipher_suite: session_id_length: {}", session_id_length);
                    
                    // Check if we have enough bytes for session_id + cipher_suite + compression_method
                    if body.len() >= 35 + session_id_length + 2 + 1 {
                        let cipher_suite_offset = 35 + session_id_length;
                        let cipher_suite = (body[cipher_suite_offset] as u16) << 8 | body[cipher_suite_offset + 1] as u16;
                        debug_print!("DEBUG parse_server_cipher_suite: cipher_suite_offset: {}", cipher_suite_offset);
                        debug_print!("DEBUG parse_server_cipher_suite: Raw cipher suite: 0x{:04x}", cipher_suite);
                    
                        match cipher_suite {
                            0x1301 | 0x1302 | 0x1303 => {
                                debug_print!("DEBUG parse_server_cipher_suite: Supported TLS 1.3 cipher suite: 0x{:04x}", cipher_suite);
                                return Ok(cipher_suite);
                            }
                            _ => {
                                debug_print!("DEBUG parse_server_cipher_suite: Unsupported cipher suite: 0x{:04x}", cipher_suite);
                                return Err(VefasError::invalid_input(
                                    "server_hello",
                                    &format!("Unsupported cipher suite: 0x{:04x}", cipher_suite),
                                ));
                            }
                        }
                    } else {
                        return Err(VefasError::invalid_input(
                            "server_hello",
                            &format!("ServerHello body too short for session_id_length {}: {} bytes", session_id_length, body.len()),
                        ));
                    }
                } else {
                    debug_print!("DEBUG parse_server_cipher_suite: Body too short: {} bytes", body.len());
                    return Err(VefasError::invalid_input(
                        "server_hello",
                        &format!("ServerHello body too short: {} bytes", body.len()),
                    ));
                }
            } else {
                debug_print!("DEBUG parse_server_cipher_suite: Invalid message length: {} (expected >= 38)", msg_len);
                return Err(VefasError::invalid_input(
                    "server_hello",
                    &format!("Invalid ServerHello length: {} (expected >= 38)", msg_len),
                ));
            }
        } else {
            debug_print!("DEBUG parse_server_cipher_suite: Not a ServerHello message: 0x{:02x}", msg_type);
            return Err(VefasError::invalid_input(
                "server_hello",
                &format!("Not a ServerHello message: 0x{:02x}", msg_type),
            ));
        }
    }

    debug_print!("DEBUG parse_server_cipher_suite: ServerHello message not found or invalid format");
    Err(VefasError::invalid_input(
        "server_hello",
        "ServerHello message not found or invalid format"
    ))
}

/// Parse server key_share extension from ServerHello using tls-parser
pub fn parse_server_hello_key_share(server_hello: &[u8]) -> VefasResult<KeyShare> {
    // Parse the TLS record containing ServerHello
    let (_, record) = parse_tls_plaintext(server_hello)
        .map_err(|e| VefasError::invalid_input("server_hello", &format!("Failed to parse TLS record: {:?}", e)))?;

    // Extract the handshake message
    for msg in record.msg {
        if let TlsMessage::Handshake(TlsMessageHandshake::ServerHello(hello)) = msg {
            // Look for key_share extension (0x0033)
            if let Some(ext) = hello.ext {
                // Use tls-parser's extension parsing
                match parse_tls_extensions(ext) {
                    Ok((_, extensions)) => {
                        for extension in extensions {
                            if let TlsExtension::KeyShare(key_share_data) = extension {
                                // Parse key_share extension format (ServerHello): [group(2)][key_exchange_len(2)][key_exchange]
                                if key_share_data.len() < 4 {
                                    return Err(VefasError::invalid_input(
                                        "server_hello",
                                        "Key share extension too short"
                                    ));
                                }

                                // Read group (2 bytes)
                                let group = u16::from_be_bytes([key_share_data[0], key_share_data[1]]);

                                // Read key_exchange_len (2 bytes)
                                let key_len = u16::from_be_bytes([key_share_data[2], key_share_data[3]]) as usize;

                                if key_share_data.len() < 4 + key_len {
                                    return Err(VefasError::invalid_input(
                                        "server_hello",
                                        "Key exchange data too short"
                                    ));
                                }

                                // Extract key_exchange
                                let key_exchange = key_share_data[4..4 + key_len].to_vec();
                                return Ok(KeyShare {
                                    group,
                                    key_exchange,
                                });
                            }
                        }
                    }
                    Err(_) => {
                        // Fallback to manual parsing if tls-parser fails
                        return parse_key_share_manual(ext);
                    }
                }
            }

            return Err(VefasError::invalid_input(
                "server_hello",
                "Key share extension not found in ServerHello"
            ));
        }
    }

    Err(VefasError::invalid_input(
        "server_hello",
        "ServerHello message not found in TLS record"
    ))
}

/// Manual parsing fallback for key share extension
fn parse_key_share_manual(ext: &[u8]) -> VefasResult<KeyShare> {
    let mut offset = 0;
    while offset + 4 <= ext.len() {
        let ext_type = (ext[offset] as u16) << 8 | ext[offset + 1] as u16;
        let ext_len = (ext[offset + 2] as u16) << 8 | ext[offset + 3] as u16;
        
        if ext_type == 0x0033 {
            // key_share extension format (ServerHello): [group(2)][key_exchange_len(2)][key_exchange]
            let data = &ext[offset + 4..offset + 4 + ext_len as usize];
            if data.len() < 4 {
                return Err(VefasError::invalid_input(
                    "server_hello",
                    "Key share extension too short"
                ));
            }

            // Read group (2 bytes)
            let group = u16::from_be_bytes([data[0], data[1]]);

            // Read key_exchange_len (2 bytes)
            let key_len = u16::from_be_bytes([data[2], data[3]]) as usize;

            if data.len() < 4 + key_len {
                return Err(VefasError::invalid_input(
                    "server_hello",
                    "Key exchange data too short"
                ));
            }

            // Extract key_exchange
            let key_exchange = data[4..4 + key_len].to_vec();
            return Ok(KeyShare {
                group,
                key_exchange,
            });
        }
        
        offset += 4 + ext_len as usize;
    }

    Err(VefasError::invalid_input(
        "server_hello",
        "Key share extension not found in manual parsing"
    ))
}

/// Get cipher suite name from ID
pub fn cipher_suite_name(id: u16) -> &'static str {
    match id {
        0x1301 => "TLS_AES_128_GCM_SHA256",
        0x1302 => "TLS_AES_256_GCM_SHA384",
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
        _ => "UNKNOWN",
    }
}

/// Convert cipher suite ID to enum
pub fn cipher_suite_from_id(id: u16) -> Option<CipherSuite> {
    match id {
        0x1301 => Some(CipherSuite::Aes128GcmSha256),
        0x1302 => Some(CipherSuite::Aes256GcmSha384),
        0x1303 => Some(CipherSuite::ChaCha20Poly1305Sha256),
        _ => None,
    }
}

/// Compute transcript hash for TLS 1.3 handshake messages
pub fn compute_transcript_hash<C: VefasCrypto>(
    crypto: &C,
    messages: &[&[u8]],
    cipher_suite: CipherSuite,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    for msg in messages {
        transcript.extend_from_slice(msg);
    }

    match cipher_suite {
        CipherSuite::Aes128GcmSha256
        | CipherSuite::ChaCha20Poly1305Sha256 => crypto.sha256(&transcript).to_vec(),
        CipherSuite::Aes256GcmSha384 => crypto.sha384(&transcript).to_vec(),
    }
}

/// HKDF-Expand-Label implementation for TLS 1.3 with cipher suite support (RFC 8446 §7.1)
///
/// This function automatically selects the correct hash function (SHA-256 or SHA-384)
/// based on the cipher suite.
pub fn hkdf_expand_label_for_cipher<C: VefasCrypto>(
    crypto: &C,
    cipher_suite: CipherSuite,
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> VefasResult<Vec<u8>> {
    debug_print!("DEBUG hkdf_expand_label_for_cipher: cipher={:?}, prk.len()={}, label={:?}, length={}",
        cipher_suite, prk.len(),
        core::str::from_utf8(label).unwrap_or("<binary>"),
        length);

    // Construct HkdfLabel structure
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());

    // Length (2 bytes)
    info.extend_from_slice(&(length as u16).to_be_bytes());

    // Label length + "tls13 " + label
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);

    // Context length + context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    // Use cipher-suite-appropriate HKDF
    let result = match cipher_suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 => {
            debug_print!("DEBUG hkdf_expand_label_for_cipher: Using SHA-256 HKDF");
            // SHA-256 based cipher suites: 32-byte secrets
            if prk.len() != 32 {
                debug_print!("ERROR hkdf_expand_label_for_cipher: PRK length mismatch for SHA-256! expected=32, got={}", prk.len());
                return Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::InvalidKeyLength,
                    "PRK must be 32 bytes for SHA-256 cipher suites",
                ));
            }
            let mut prk_array = [0u8; 32];
            prk_array.copy_from_slice(prk);
            crypto.hkdf_expand(&prk_array, &info, length)?
        }
        CipherSuite::Aes256GcmSha384 => {
            debug_print!("DEBUG hkdf_expand_label_for_cipher: Using SHA-384 HKDF");
            // SHA-384 based cipher suite: 48-byte secrets
            if prk.len() != 48 {
                debug_print!("ERROR hkdf_expand_label_for_cipher: PRK length mismatch for SHA-384! expected=48, got={}", prk.len());
                return Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::InvalidKeyLength,
                    "PRK must be 48 bytes for SHA-384 cipher suites",
                ));
            }
            let mut prk_array = [0u8; 48];
            prk_array.copy_from_slice(prk);
            crypto.hkdf_expand_sha384(&prk_array, &info, length)?
        }
    };

    debug_print!("DEBUG hkdf_expand_label_for_cipher: HKDF expand succeeded, output.len()={}", result.len());
    Ok(result)
}

/// HKDF-Expand-Label implementation for TLS 1.3 (RFC 8446 §7.1)
///
/// Legacy function for backward compatibility. Use `hkdf_expand_label_for_cipher` for cipher-suite awareness.
pub fn hkdf_expand_label<C: VefasCrypto>(
    crypto: &C,
    prk: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> VefasResult<Vec<u8>> {
    // Construct HkdfLabel structure
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1 + context.len());

    // Length (2 bytes)
    info.extend_from_slice(&(length as u16).to_be_bytes());

    // Label length + "tls13 " + label
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);

    // Context length + context
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    // Convert PRK to fixed-size array for trait consistency
    let prk_array: [u8; 32] = if prk.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&prk[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..prk.len()].copy_from_slice(prk);
        arr
    };

    crypto.hkdf_expand(&prk_array, &info, length)
}

/// Remove TLS 1.3 padding and inner content type from plaintext
pub fn remove_tls13_padding(plaintext: &mut Vec<u8>) -> VefasResult<()> {
    if plaintext.is_empty() {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Empty plaintext after decryption",
        ));
    }

    // Remove trailing zero padding
    while let Some(&0) = plaintext.last() {
        plaintext.pop();
    }

    // Remove the inner content type byte
    if !plaintext.is_empty() {
        plaintext.pop();
    } else {
        return Err(VefasError::invalid_input(
            "tls_record",
            "No inner content type found",
        ));
    }

    Ok(())
}

/// Decrypt TLS 1.3 application data record with full cipher suite support
///
/// Supports all three TLS 1.3 cipher suites:
/// - TLS_AES_128_GCM_SHA256 (0x1301)
/// - TLS_AES_256_GCM_SHA384 (0x1302)
/// - TLS_CHACHA20_POLY1305_SHA256 (0x1303)
pub fn decrypt_application_record<C: VefasCrypto>(
    crypto: &C,
    records: &[u8],
    traffic_secret: &[u8],
    mut sequence_number: u64,
    cipher_suite: CipherSuite,
) -> VefasResult<Vec<u8>> {
    debug_print!("DEBUG: decrypt_application_record called!");
    // DEBUG: Log entry parameters
    debug_print!("DEBUG decrypt_application_record: cipher_suite={:?} (0x{:04x})",
        cipher_suite,
        match cipher_suite {
            CipherSuite::Aes128GcmSha256 => 0x1301u16,
            CipherSuite::Aes256GcmSha384 => 0x1302u16,
            CipherSuite::ChaCha20Poly1305Sha256 => 0x1303u16,
        }
    );
    debug_print!("DEBUG decrypt_application_record: traffic_secret.len()={}, seq={}, records.len()={}",
        traffic_secret.len(), sequence_number, records.len());
    debug_print!("DEBUG decrypt_application_record: traffic_secret first 8 bytes: {:02x?}", &traffic_secret[..8.min(traffic_secret.len())]);
    debug_print!("DEBUG decrypt_application_record: total records bytes={}", records.len());
    debug_print!("DEBUG decrypt_application_record: About to validate traffic secret length...");

    // Validate traffic secret length based on cipher suite
    let expected_secret_len = match cipher_suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 => 32,
        CipherSuite::Aes256GcmSha384 => 48,
    };

    debug_print!("DEBUG decrypt_application_record: expected_secret_len={}", expected_secret_len);

    if traffic_secret.len() != expected_secret_len {
        debug_print!("ERROR decrypt_application_record: Traffic secret length mismatch! expected={}, got={}",
            expected_secret_len, traffic_secret.len());
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "Traffic secret length doesn't match cipher suite",
        ));
    }

    // Derive traffic keys ONCE with cipher-suite-specific sizes
    let (key_len, iv_len) = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => (16, 12),  // AES-128 key, 12-byte IV
        CipherSuite::Aes256GcmSha384 => (32, 12),  // AES-256 key, 12-byte IV
        CipherSuite::ChaCha20Poly1305Sha256 => (32, 12),  // ChaCha20 key, 12-byte IV
    };

    debug_print!("DEBUG decrypt_application_record: BEFORE KEY DERIVATION");
    debug_print!("DEBUG decrypt_application_record: Traffic secret: {:02x?}", traffic_secret);
    debug_print!("DEBUG decrypt_application_record: Deriving key_len={}, iv_len={}", key_len, iv_len);

    let key = hkdf_expand_label_for_cipher(crypto, cipher_suite, traffic_secret, b"key", &[], key_len)?;
    debug_print!("DEBUG decrypt_application_record: AFTER KEY DERIVATION");
    debug_print!("DEBUG decrypt_application_record: Derived key: {:02x?}", key);
    debug_print!("DEBUG decrypt_application_record: Key derived, actual key.len()={}", key.len());

    let iv = hkdf_expand_label_for_cipher(crypto, cipher_suite, traffic_secret, b"iv", &[], iv_len)?;
    debug_print!("DEBUG decrypt_application_record: AFTER IV DERIVATION");
    debug_print!("DEBUG decrypt_application_record: Derived IV: {:02x?}", iv);
    debug_print!("DEBUG decrypt_application_record: IV derived, actual iv.len()={}", iv.len());

    if key.len() != key_len || iv.len() != iv_len {
        debug_print!("ERROR decrypt_application_record: Key/IV length mismatch! key: expected={}, got={}, iv: expected={}, got={}",
            key_len, key.len(), iv_len, iv.len());
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "Invalid key/IV length from HKDF",
        ));
    }

    let mut static_iv = [0u8; 12];
    static_iv.copy_from_slice(&iv);

    // Accumulator for all decrypted plaintexts
    let mut all_plaintext = Vec::new();

    // Parse and decrypt each TLS record in the byte stream
    let mut offset = 0;
    let mut record_count = 0;

    while offset < records.len() {
        // First, peek at the header to get the declared length
        if offset + 5 > records.len() {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} header extends beyond available data", record_count),
            ));
        }

        // Extract content type and declared length from header
        let content_type = records[offset];
        let declared_len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;

        // Calculate this record's end position
        let record_end = offset + 5 + declared_len;
        if record_end > records.len() {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} extends beyond available data", record_count),
            ));
        }

        // Get the exact bytes for this record only
        let this_record = &records[offset..record_end];

        // Must be application data
        if content_type != 23 {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} is not application_data", record_count),
            ));
        }

        // Additional length validations
        if declared_len < 16 {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} declared length too short for AEAD", record_count),
            ));
        }

        // AAD is the 5-byte record header
        let aad = &this_record[..5];
        let ciphertext = &this_record[5..];

        // Derive per-record nonce = static_iv XOR seq (RFC 8446 §5.3)
        // Each record uses its own sequence number
        debug_print!("DEBUG decrypt_application_record: Record {}: BEFORE NONCE DERIVATION", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Static IV: {:02x?}", record_count, static_iv);
        debug_print!("DEBUG decrypt_application_record: Record {}: Sequence number: {}", record_count, sequence_number);
        
        let nonce = derive_aead_nonce_internal(&static_iv, sequence_number)?;

        debug_print!("DEBUG decrypt_application_record: Record {}: AFTER NONCE DERIVATION", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Nonce derived for seq {}", record_count, sequence_number);
        debug_print!("DEBUG decrypt_application_record: Record {}: Nonce: {:02x?}", record_count, nonce);
        debug_print!("DEBUG decrypt_application_record: Record {}: Key: {:02x?}", record_count, &key[..8]);
        debug_print!("DEBUG decrypt_application_record: Record {}: AAD: {:02x?}", record_count, aad);
        debug_print!("DEBUG decrypt_application_record: Record {}: About to decrypt - ciphertext.len()={}, aad.len()={}",
            record_count, ciphertext.len(), aad.len());
        debug_print!("DEBUG decrypt_application_record: Record {}: Ciphertext first 16 bytes: {:02x?}", record_count, &ciphertext[..16.min(ciphertext.len())]);

        // Decrypt using cipher-suite-specific AEAD
        debug_print!("DEBUG decrypt_application_record: Record {}: BEFORE DECRYPTION", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Full Key: {:02x?}", record_count, key);
        debug_print!("DEBUG decrypt_application_record: Record {}: Full Nonce: {:02x?}", record_count, nonce);
        debug_print!("DEBUG decrypt_application_record: Record {}: Full AAD: {:02x?}", record_count, aad);
        debug_print!("DEBUG decrypt_application_record: Record {}: Full Ciphertext: {:02x?}", record_count, ciphertext);
        
        let mut plaintext = match cipher_suite {
            CipherSuite::Aes128GcmSha256 => {
                debug_print!("DEBUG decrypt_application_record: Record {}: Using AES-128-GCM decryption", record_count);
                let mut key_arr = [0u8; 16];
                key_arr.copy_from_slice(&key);
                debug_print!("DEBUG decrypt_application_record: Record {}: AES-128 Key Array: {:02x?}", record_count, key_arr);
                let result = crypto.aes_128_gcm_decrypt(&key_arr, &nonce, aad, ciphertext);
                debug_print!("DEBUG decrypt_application_record: Record {}: AES-128-GCM result: {:?}", record_count, result);
                result?
            }
            CipherSuite::Aes256GcmSha384 => {
                debug_print!("DEBUG decrypt_application_record: Record {}: Using AES-256-GCM decryption", record_count);
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(&key);
                debug_print!("DEBUG decrypt_application_record: Record {}: AES-256 Key Array: {:02x?}", record_count, key_arr);
                let result = crypto.aes_256_gcm_decrypt(&key_arr, &nonce, aad, ciphertext);
                debug_print!("DEBUG decrypt_application_record: Record {}: AES-256-GCM result: {:?}", record_count, result);
                
                // VALIDATION: Check if decryption succeeded
                match &result {
                    Ok(plaintext) => {
                        debug_print!("DEBUG decrypt_application_record: Record {}: DECRYPTION SUCCESS!", record_count);
                        debug_print!("DEBUG decrypt_application_record: Record {}: Decrypted plaintext length: {}", record_count, plaintext.len());
                        debug_print!("DEBUG decrypt_application_record: Record {}: Decrypted plaintext first 32 bytes: {:02x?}", record_count, &plaintext[..32.min(plaintext.len())]);
                    }
                    Err(e) => {
                        debug_print!("DEBUG decrypt_application_record: Record {}: DECRYPTION FAILED!", record_count);
                        debug_print!("DEBUG decrypt_application_record: Record {}: Error: {:?}", record_count, e);
                        
                        // VALIDATION: Try to identify the specific failure
                        debug_print!("DEBUG decrypt_application_record: Record {}: FAILURE ANALYSIS:", record_count);
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Key length: {}", record_count, key.len());
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Nonce length: {}", record_count, nonce.len());
                        debug_print!("DEBUG decrypt_application_record: Record {}: - AAD length: {}", record_count, aad.len());
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Ciphertext length: {}", record_count, ciphertext.len());
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Sequence number: {}", record_count, sequence_number);
                        
                        // VALIDATION: Check if parameters are reasonable
                        debug_print!("DEBUG decrypt_application_record: Record {}: PARAMETER VALIDATION:", record_count);
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Key is all zeros: {}", record_count, key.iter().all(|&b| b == 0));
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Nonce is all zeros: {}", record_count, nonce.iter().all(|&b| b == 0));
                        debug_print!("DEBUG decrypt_application_record: Record {}: - AAD is all zeros: {}", record_count, aad.iter().all(|&b| b == 0));
                        debug_print!("DEBUG decrypt_application_record: Record {}: - Ciphertext is all zeros: {}", record_count, ciphertext.iter().all(|&b| b == 0));
                    }
                }
                
                result?
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                debug_print!("DEBUG decrypt_application_record: Record {}: Using ChaCha20-Poly1305 decryption", record_count);
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(&key);
                debug_print!("DEBUG decrypt_application_record: Record {}: ChaCha20 Key Array: {:02x?}", record_count, key_arr);
                let result = crypto.chacha20_poly1305_decrypt(&key_arr, &nonce, aad, ciphertext);
                debug_print!("DEBUG decrypt_application_record: Record {}: ChaCha20-Poly1305 result: {:?}", record_count, result);
                result?
            }
        };
        
        debug_print!("DEBUG decrypt_application_record: Record {}: AFTER DECRYPTION", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Plaintext length: {}", record_count, plaintext.len());
        debug_print!("DEBUG decrypt_application_record: Record {}: Plaintext first 32 bytes: {:02x?}", record_count, &plaintext[..32.min(plaintext.len())]);

        debug_print!("DEBUG decrypt_application_record: Record {}: Decryption succeeded, plaintext.len()={}", record_count, plaintext.len());

        // Remove TLS 1.3 padding and inner content type
        debug_print!("DEBUG decrypt_application_record: Record {}: BEFORE PADDING REMOVAL", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Plaintext before padding removal: {:02x?}", record_count, plaintext);
        
        let padding_result = remove_tls13_padding(&mut plaintext);
        debug_print!("DEBUG decrypt_application_record: Record {}: Padding removal result: {:?}", record_count, padding_result);
        padding_result?;

        debug_print!("DEBUG decrypt_application_record: Record {}: AFTER PADDING REMOVAL", record_count);
        debug_print!("DEBUG decrypt_application_record: Record {}: Plaintext after padding removal: {:02x?}", record_count, plaintext);
        debug_print!("DEBUG decrypt_application_record: Record {}: After padding removal, plaintext.len()={}", record_count, plaintext.len());

        // Accumulate this record's plaintext
        all_plaintext.extend_from_slice(&plaintext);

        // Move to next record
        offset = record_end;
        sequence_number += 1;
        record_count += 1;
    }

    debug_print!("DEBUG decrypt_application_record: Decrypted {} records, total plaintext.len()={}", record_count, all_plaintext.len());

    Ok(all_plaintext)
}

/// Decrypt TLS 1.3 application data records with mixed traffic secrets
///
/// This function handles the case where different ApplicationData records
/// are encrypted with different traffic secrets (e.g., HTTP data with
/// application traffic secrets, Client Finished with handshake traffic secrets).
///
/// It tries both traffic secrets for each record and returns the successful
/// decryption result.
pub fn decrypt_application_record_mixed<C: VefasCrypto>(
    crypto: &C,
    records: &[u8],
    handshake_traffic_secret: &[u8],
    application_traffic_secret: &[u8],
    mut sequence_number: u64,
    cipher_suite: CipherSuite,
) -> VefasResult<Vec<u8>> {
    debug_print!("DEBUG: decrypt_application_record_mixed called!");
    debug_print!("DEBUG: handshake_traffic_secret.len()={}, application_traffic_secret.len()={}", 
        handshake_traffic_secret.len(), application_traffic_secret.len());
    debug_print!("DEBUG: sequence_number={}, records.len()={}", sequence_number, records.len());

    // Validate traffic secret lengths based on cipher suite
    let expected_secret_len = match cipher_suite {
        CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 => 32,
        CipherSuite::Aes256GcmSha384 => 48,
    };

    if handshake_traffic_secret.len() != expected_secret_len {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "Handshake traffic secret length doesn't match cipher suite",
        ));
    }

    if application_traffic_secret.len() != expected_secret_len {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "Application traffic secret length doesn't match cipher suite",
        ));
    }

    // Derive traffic keys for both secrets
    let (key_len, iv_len) = match cipher_suite {
        CipherSuite::Aes128GcmSha256 => (16, 12),  // AES-128 key, 12-byte IV
        CipherSuite::Aes256GcmSha384 => (32, 12),  // AES-256 key, 12-byte IV
        CipherSuite::ChaCha20Poly1305Sha256 => (32, 12),  // ChaCha20 key, 12-byte IV
    };

    // Derive keys for handshake traffic secret
    let hs_key = hkdf_expand_label_for_cipher(crypto, cipher_suite, handshake_traffic_secret, b"key", &[], key_len)?;
    let hs_iv = hkdf_expand_label_for_cipher(crypto, cipher_suite, handshake_traffic_secret, b"iv", &[], iv_len)?;

    // Derive keys for application traffic secret
    let app_key = hkdf_expand_label_for_cipher(crypto, cipher_suite, application_traffic_secret, b"key", &[], key_len)?;
    let app_iv = hkdf_expand_label_for_cipher(crypto, cipher_suite, application_traffic_secret, b"iv", &[], iv_len)?;

    debug_print!("DEBUG: Derived HS key: {:02x?}", &hs_key[..8]);
    debug_print!("DEBUG: Derived HS IV: {:02x?}", hs_iv);
    debug_print!("DEBUG: Derived APP key: {:02x?}", &app_key[..8]);
    debug_print!("DEBUG: Derived APP IV: {:02x?}", app_iv);

    // Accumulator for all decrypted plaintexts
    let mut all_plaintext = Vec::new();

    // Parse and decrypt each TLS record in the byte stream
    let mut offset = 0;
    let mut record_count = 0;

    while offset < records.len() {
        // First, peek at the header to get the declared length
        if offset + 5 > records.len() {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} header extends beyond available data", record_count),
            ));
        }

        // Extract content type and declared length from header
        let content_type = records[offset];
        let declared_len = u16::from_be_bytes([records[offset + 3], records[offset + 4]]) as usize;

        // Calculate this record's end position
        let record_end = offset + 5 + declared_len;
        if record_end > records.len() {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} extends beyond available data", record_count),
            ));
        }

        // Get the exact bytes for this record only
        let this_record = &records[offset..record_end];

        // Must be application data
        if content_type != 23 {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} is not application_data", record_count),
            ));
        }

        // Additional length validations
        if declared_len < 16 {
            return Err(VefasError::invalid_input(
                "tls_record",
                &format!("Record {} declared length too short for AEAD", record_count),
            ));
        }

        // AAD is the 5-byte record header
        let aad = &this_record[..5];
        let ciphertext = &this_record[5..];

        debug_print!("DEBUG: Record {}: Trying both traffic secrets for seq {}", record_count, sequence_number);

        // Try handshake traffic secret first
        let hs_nonce = derive_aead_nonce_internal(&hs_iv, sequence_number)?;
        debug_print!("DEBUG: Record {}: HS nonce: {:02x?}", record_count, hs_nonce);

        let hs_result = match cipher_suite {
            CipherSuite::Aes128GcmSha256 => {
                let mut key_arr = [0u8; 16];
                key_arr.copy_from_slice(&hs_key);
                crypto.aes_128_gcm_decrypt(&key_arr, &hs_nonce, aad, ciphertext)
            }
            CipherSuite::Aes256GcmSha384 => {
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(&hs_key);
                crypto.aes_256_gcm_decrypt(&key_arr, &hs_nonce, aad, ciphertext)
            }
            CipherSuite::ChaCha20Poly1305Sha256 => {
                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(&hs_key);
                crypto.chacha20_poly1305_decrypt(&key_arr, &hs_nonce, aad, ciphertext)
            }
        };

        match hs_result {
            Ok(plaintext) => {
                debug_print!("DEBUG: Record {}: SUCCESS with handshake traffic secret! plaintext.len()={}", record_count, plaintext.len());
                debug_print!("DEBUG: Record {}: Plaintext first 16 bytes: {:02x?}", record_count, &plaintext[..16.min(plaintext.len())]);
                all_plaintext.extend_from_slice(&plaintext);
            }
            Err(_) => {
                debug_print!("DEBUG: Record {}: Failed with handshake traffic secret, trying application traffic secret", record_count);
                
                // Try application traffic secret
                let app_nonce = derive_aead_nonce_internal(&app_iv, sequence_number)?;
                debug_print!("DEBUG: Record {}: APP nonce: {:02x?}", record_count, app_nonce);

                let app_result = match cipher_suite {
                    CipherSuite::Aes128GcmSha256 => {
                        let mut key_arr = [0u8; 16];
                        key_arr.copy_from_slice(&app_key);
                        crypto.aes_128_gcm_decrypt(&key_arr, &app_nonce, aad, ciphertext)
                    }
                    CipherSuite::Aes256GcmSha384 => {
                        let mut key_arr = [0u8; 32];
                        key_arr.copy_from_slice(&app_key);
                        crypto.aes_256_gcm_decrypt(&key_arr, &app_nonce, aad, ciphertext)
                    }
                    CipherSuite::ChaCha20Poly1305Sha256 => {
                        let mut key_arr = [0u8; 32];
                        key_arr.copy_from_slice(&app_key);
                        crypto.chacha20_poly1305_decrypt(&key_arr, &app_nonce, aad, ciphertext)
                    }
                };

                match app_result {
                    Ok(plaintext) => {
                        debug_print!("DEBUG: Record {}: SUCCESS with application traffic secret! plaintext.len()={}", record_count, plaintext.len());
                        debug_print!("DEBUG: Record {}: Plaintext first 16 bytes: {:02x?}", record_count, &plaintext[..16.min(plaintext.len())]);
                        all_plaintext.extend_from_slice(&plaintext);
                    }
                    Err(e) => {
                        debug_print!("DEBUG: Record {}: FAILED with both traffic secrets: {:?}", record_count, e);
                        return Err(e);
                    }
                }
            }
        }

        // Move to next record
        offset = record_end;
        sequence_number += 1;
        record_count += 1;
    }

    debug_print!("DEBUG: decrypt_application_record_mixed: Decrypted {} records, total plaintext.len()={}", record_count, all_plaintext.len());

    Ok(all_plaintext)
}

/// Internal implementation of derive_aead_nonce for use within tls_parser
/// This is a copy of the function that was moved to vefas-crypto-native
fn derive_aead_nonce_internal(static_iv: &[u8], sequence_number: u64) -> VefasResult<[u8; 12]> {
    if static_iv.len() != 12 {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidNonceLength,
            "TLS 1.3 IV must be 12 bytes",
        ));
    }

    // Create 12-byte nonce with seq in the last 8 bytes (big-endian), first 4 bytes zero
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&sequence_number.to_be_bytes());

    // XOR with static IV
    let mut out = [0u8; 12];
    for i in 0..12 {
        out[i] = static_iv[i] ^ nonce[i];
    }
    Ok(out)
}

/// Validate basic handshake message structure using tls-parser
pub fn validate_handshake_message(msg: &[u8], expected_type: u8) -> VefasResult<&[u8]> {
    // Try parsing as raw handshake first
    if msg.len() >= 4 {
        let msg_type = msg[0];
        let msg_len = ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | (msg[3] as usize);
        if msg_type == expected_type && msg.len() >= 4 + msg_len {
            return Ok(&msg[4..4 + msg_len]);
        }
    }

    // Try parsing as TLS record containing handshake
    if let Ok((remaining, record)) = parse_tls_plaintext(msg) {
        if remaining.is_empty() && record.hdr.record_type == TlsRecordType::Handshake {
            for message in record.msg {
                if let TlsMessage::Handshake(handshake) = message {
                    let msg_type = match handshake {
                        TlsMessageHandshake::ClientHello(_) => 0x01,
                        TlsMessageHandshake::ServerHello(_) => 0x02,
                        TlsMessageHandshake::Certificate(_) => 0x0b,
                        TlsMessageHandshake::CertificateVerify(_) => 0x0f,
                        TlsMessageHandshake::Finished(_) => 0x14,
                        _ => continue,
                    };

                    if msg_type == expected_type {
                        return Ok(&msg[4..]);
                    }
                }
            }
        }
    }

    Err(VefasError::invalid_input(
        "handshake",
        "Unexpected handshake message type",
    ))
}

/// Validate ClientHello message structure
pub fn validate_client_hello(client_hello: &[u8]) -> VefasResult<()> {
    validate_handshake_message(client_hello, 0x01)?;
    Ok(())
}

/// Validate ServerHello message structure
pub fn validate_server_hello(server_hello: &[u8]) -> VefasResult<()> {
    validate_handshake_message(server_hello, 0x02)?;
    Ok(())
}

/// Validate Certificate message structure
pub fn validate_certificate_message(cert_msg: &[u8]) -> VefasResult<()> {
    validate_handshake_message(cert_msg, 0x0b)?;
    Ok(())
}

/// Validate CertificateVerify message structure
pub fn validate_certificate_verify(cert_verify: &[u8]) -> VefasResult<()> {
    validate_handshake_message(cert_verify, 0x0f)?;
    Ok(())
}

/// Validate Finished message structure
pub fn validate_finished_message(finished: &[u8]) -> VefasResult<()> {
    validate_handshake_message(finished, 0x14)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn parse_handshake_header_valid_raw() {
        let msg = [0x01, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5]; // ClientHello with 5-byte body
        let result = parse_handshake_header(&msg);
        assert!(result.is_some());
        let (msg_type, len, body) = result.unwrap();
        assert_eq!(msg_type, 0x01);
        assert_eq!(len, 5);
        assert_eq!(body, &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn parse_handshake_header_invalid_type() {
        let msg = [0xFF, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5]; // Invalid handshake type
        let result = parse_handshake_header(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn parse_handshake_header_too_short() {
        let msg = [0x01, 0x00, 0x00]; // Missing body
        let result = parse_handshake_header(&msg);
        assert!(result.is_none());
    }

    #[test]
    fn parse_server_cipher_suite_valid() {
        // Build minimal valid ServerHello
        let mut sh = Vec::new();
        sh.extend_from_slice(&[0x02, 0x00, 0x00, 38]); // handshake header (ServerHello, length 38)
        sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
        sh.extend_from_slice(&[0u8; 32]); // random
        sh.push(0); // session_id_length
        sh.extend_from_slice(&[0x13, 0x01]); // cipher_suite (TLS_AES_128_GCM_SHA256)
        sh.push(0); // compression_method


        let result = parse_server_cipher_suite(&sh);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0x1301);
    }

    #[test]
    fn parse_server_cipher_suite_unsupported() {
        // Build ServerHello with unsupported cipher suite
        let mut sh = Vec::new();
        sh.extend_from_slice(&[0x02, 0x00, 0x00, 38]); // handshake header
        sh.extend_from_slice(&[0x03, 0x03]); // legacy_version
        sh.extend_from_slice(&[0u8; 32]); // random
        sh.push(0); // session_id_length
        sh.extend_from_slice(&[0x00, 0x35]); // unsupported cipher suite
        sh.push(0); // compression_method

        let result = parse_server_cipher_suite(&sh);
        assert!(result.is_err());
    }

    #[test]
    fn cipher_suite_names() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(cipher_suite_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256");
        assert_eq!(cipher_suite_name(0x9999), "UNKNOWN");
    }

    #[test]
    fn cipher_suite_from_id_valid() {
        assert_eq!(
            cipher_suite_from_id(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            cipher_suite_from_id(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
        assert_eq!(
            cipher_suite_from_id(0x1303),
            Some(CipherSuite::ChaCha20Poly1305Sha256)
        );
    }

    #[test]
    fn cipher_suite_from_id_invalid() {
        assert_eq!(cipher_suite_from_id(0x9999), None);
    }

    #[test]
    fn remove_tls13_padding_valid() {
        let mut plaintext = vec![1, 2, 3, 4, 0x16, 0, 0, 0]; // data + content type + padding
        let result = remove_tls13_padding(&mut plaintext);
        assert!(result.is_ok());
        assert_eq!(plaintext, vec![1, 2, 3, 4]); // padding and content type removed
    }

    #[test]
    fn remove_tls13_padding_empty() {
        let mut plaintext = vec![];
        let result = remove_tls13_padding(&mut plaintext);
        assert!(result.is_err());
    }

    #[test]
    fn validate_client_hello_valid() {
        let ch = [0x01, 0x00, 0x00, 0x00]; // ClientHello with empty body
        let result = validate_client_hello(&ch);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_client_hello_wrong_type() {
        let ch = [0x02, 0x00, 0x00, 0x00]; // ServerHello instead of ClientHello
        let result = validate_client_hello(&ch);
        assert!(result.is_err());
    }
}
