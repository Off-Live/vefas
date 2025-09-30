//! TLS protocol parsing utilities for VEFAS
//!
//! This module provides comprehensive TLS 1.3 message parsing capabilities
//! that can be shared across different zkVM platforms. All parsing operations
//! include rigorous bounds checking and validation to ensure secure operation
//! in zero-knowledge contexts.



use alloc::{vec::Vec, format};

use vefas_types::{VefasResult, VefasError, tls::CipherSuite};
use crate::input_validation::{SafeParser, validate_tls_record_header, validate_handshake_header, parse_24bit_length};
use crate::traits::VefasCrypto;

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

/// Parse TLS handshake header with comprehensive bounds checking
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
    if let Some(result) = parse_raw_handshake(msg) {
        return Some(result);
    }

    // Try parsing as TLS record containing handshake
    if let Some(result) = parse_tls_record_handshake(msg) {
        return Some(result);
    }

    None
}

/// Parse raw handshake message (type, len(3), body)
fn parse_raw_handshake(msg: &[u8]) -> Option<(u8, usize, &[u8])> {
    // Need at least 4 bytes for header
    if msg.len() < 4 {
        return None;
    }

    let hstype = msg[0];

    // Validate handshake type
    match hstype {
        0x01 | 0x02 | 0x0b | 0x0f | 0x14 => {}, // Valid types: ClientHello, ServerHello, Certificate, CertificateVerify, Finished
        _ => return None,
    }

    // Parse 24-bit length with overflow protection
    let hlen = parse_24bit_length(&msg[1..4])?;

    // Validate total length
    let total_len = 4_usize.checked_add(hlen)?;
    if total_len > msg.len() {
        return None;
    }

    // Validate handshake body length is reasonable
    if hlen > 32768 {
        return None;
    }

    Some((hstype, hlen, &msg[4..4 + hlen]))
}

/// Parse TLS record containing handshake message
fn parse_tls_record_handshake(msg: &[u8]) -> Option<(u8, usize, &[u8])> {
    // Need at least 5 bytes for TLS record header
    if msg.len() < 5 {
        return None;
    }

    // Check for handshake content type
    if msg[0] != 0x16 {
        return None;
    }

    // Validate TLS version (must be 1.2 or 1.3)
    let version = u16::from_be_bytes([msg[1], msg[2]]);
    match version {
        0x0303 | 0x0304 => {}, // TLS 1.2 or 1.3
        _ => return None,
    }

    // Parse record length with bounds checking
    let rlen = u16::from_be_bytes([msg[3], msg[4]]) as usize;

    // Validate record length
    if rlen == 0 || rlen > 16384 {
        return None;
    }

    let total_len = 5_usize.checked_add(rlen)?;
    if total_len > msg.len() {
        return None;
    }

    // Extract handshake message from record
    let hs = &msg[5..5 + rlen];
    parse_raw_handshake(hs)
}

/// Parse cipher suite from ServerHello with comprehensive bounds checking
pub fn parse_server_cipher_suite(server_hello: &[u8]) -> VefasResult<u16> {
    let (typ, _hlen, body) = parse_handshake_header(server_hello)
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Malformed handshake"))?;

    if typ != 0x02 {
        return Err(VefasError::invalid_input("server_hello", "Unexpected handshake type"));
    }

    // ServerHello minimum length check
    // legacy_version(2) + random(32) + session_id_length(1) + cipher_suite(2) + compression_method(1)
    if body.len() < 38 {
        return Err(VefasError::invalid_input("server_hello", "ServerHello too short (minimum 38 bytes)"));
    }

    let mut parser = SafeParser::new(body);

    // Parse legacy_version
    let _version = parser.read_u16()
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read legacy_version"))?;

    // Parse random (32 bytes)
    let _random = parser.read_bytes(32)
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read server random"))?;

    // Parse session_id_length and session_id
    let sid_len = parser.read_u8()
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read session ID length"))? as usize;

    if sid_len > 32 {
        return Err(VefasError::invalid_input("server_hello", "Session ID too long (max 32 bytes)"));
    }

    let _session_id = parser.read_bytes(sid_len)
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read session ID"))?;

    // Parse cipher_suite
    let suite = parser.read_u16()
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read cipher suite"))?;

    // Validate cipher suite is supported
    match suite {
        0x1301 | 0x1302 | 0x1303 => Ok(suite), // TLS 1.3 cipher suites
        _ => Err(VefasError::invalid_input("server_hello",
            &format!("Unsupported cipher suite: 0x{:04x}", suite)))
    }
}

/// Parse server key_share extension from ServerHello
pub fn parse_server_hello_key_share(server_hello: &[u8]) -> VefasResult<KeyShare> {
    let (typ, _hlen, body) = parse_handshake_header(server_hello)
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Malformed handshake"))?;

    if typ != 0x02 {
        return Err(VefasError::invalid_input("server_hello", "Unexpected handshake type"));
    }

    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        return Err(VefasError::invalid_input("server_hello", "ServerHello too short for key_share"));
    }

    let mut parser = SafeParser::new(body);

    // Skip legacy_version, random, session_id
    parser.skip(2); // legacy_version
    parser.skip(32); // random
    let sid_len = parser.read_u8()
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read session ID length"))? as usize;

    if sid_len > 32 {
        return Err(VefasError::invalid_input("server_hello", "Session ID too long"));
    }

    parser.skip(sid_len); // session_id
    parser.skip(2); // cipher_suite
    parser.skip(1); // compression_method

    // Parse extensions
    let ext_len = parser.read_u16()
        .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read extensions length"))? as usize;

    if parser.remaining() < ext_len {
        return Err(VefasError::invalid_input("server_hello", "Extensions length exceeds available data"));
    }

    let extensions_start = parser.offset();
    let extensions_end = extensions_start + ext_len;

    // Parse individual extensions
    while parser.offset() < extensions_end && parser.remaining() >= 4 {
        let ext_type = parser.read_u16()
            .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read extension type"))?;

        let ext_len = parser.read_u16()
            .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read extension length"))? as usize;

        if parser.remaining() < ext_len {
            return Err(VefasError::invalid_input("server_hello", "Extension length exceeds available data"));
        }

        if ext_type == 0x0033 { // key_share extension
            if ext_len < 4 {
                return Err(VefasError::invalid_input("server_hello", "key_share extension too short"));
            }

            let group = parser.read_u16()
                .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read key_share group"))?;

            let key_len = parser.read_u16()
                .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read key_share length"))? as usize;

            if parser.remaining() < key_len {
                return Err(VefasError::invalid_input("server_hello", "key_share key length exceeds available data"));
            }

            let key_data = parser.read_bytes(key_len)
                .ok_or_else(|| VefasError::invalid_input("server_hello", "Cannot read key_share data"))?;

            return Ok(KeyShare {
                group,
                key_exchange: key_data.to_vec(),
            });
        } else {
            // Skip other extensions
            parser.skip(ext_len);
        }
    }

    Err(VefasError::invalid_input("server_hello", "key_share extension not found"))
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
        CipherSuite::Aes128GcmSha256 | CipherSuite::ChaCha20Poly1305Sha256 | CipherSuite::Aes128CcmSha256 => {
            crypto.sha256(&transcript).to_vec()
        }
        CipherSuite::Aes256GcmSha384 => {
            crypto.sha384(&transcript).to_vec()
        }
    }
}

/// HKDF-Expand-Label implementation for TLS 1.3 (RFC 8446 §7.1)
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
        return Err(VefasError::invalid_input("tls_record", "Empty plaintext after decryption"));
    }

    // Remove trailing zero padding
    while let Some(&0) = plaintext.last() {
        plaintext.pop();
    }

    // Remove the inner content type byte
    if !plaintext.is_empty() {
        plaintext.pop();
    } else {
        return Err(VefasError::invalid_input("tls_record", "No inner content type found"));
    }

    Ok(())
}

/// Decrypt TLS 1.3 application data record
pub fn decrypt_application_record<C: VefasCrypto>(
    crypto: &C,
    record: &[u8],
    traffic_secret: &[u8; 32],
    sequence_number: u64,
) -> VefasResult<Vec<u8>> {
    // Validate TLS record structure
    let (content_type, _version, declared_len) = validate_tls_record_header(record)?;

    // Must be application data
    if content_type != 23 {
        return Err(VefasError::invalid_input("tls_record", "Not application_data record"));
    }

    // Additional length validations
    if declared_len < 16 {
        return Err(VefasError::invalid_input("tls_record", "Declared length too short for AES-GCM"));
    }

    // AAD is the 5-byte record header
    let aad = &record[..5];
    let ciphertext = &record[5..];

    // Derive traffic keys
    let key = hkdf_expand_label(crypto, traffic_secret, b"key", &[], 16)?;
    let iv = hkdf_expand_label(crypto, traffic_secret, b"iv", &[], 12)?;

    if key.len() != 16 || iv.len() != 12 {
        return Err(VefasError::crypto_error(
            vefas_types::errors::CryptoErrorType::InvalidKeyLength,
            "Invalid key/IV length from HKDF"
        ));
    }

    let mut key_arr = [0u8; 16];
    key_arr.copy_from_slice(&key);
    let mut static_iv = [0u8; 12];
    static_iv.copy_from_slice(&iv);

    // Derive per-record nonce = static_iv XOR seq (RFC 8446 §5.3)
    let nonce = crate::derive_aead_nonce(&static_iv, sequence_number)?;

    // Decrypt using AES-GCM
    let mut plaintext = crypto.aes_128_gcm_decrypt(&key_arr, &nonce, aad, ciphertext)?;

    // Remove TLS 1.3 padding and inner content type
    remove_tls13_padding(&mut plaintext)?;

    Ok(plaintext)
}

/// Validate basic handshake message structure
pub fn validate_handshake_message(msg: &[u8], expected_type: u8) -> VefasResult<&[u8]> {
    let (msg_type, _length) = validate_handshake_header(msg)?;

    if msg_type != expected_type {
        return Err(VefasError::invalid_input("handshake", "Unexpected handshake message type"));
    }

    // Return the handshake body (skip 4-byte header)
    Ok(&msg[4..])
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
        assert_eq!(cipher_suite_from_id(0x1301), Some(CipherSuite::Aes128GcmSha256));
        assert_eq!(cipher_suite_from_id(0x1302), Some(CipherSuite::Aes256GcmSha384));
        assert_eq!(cipher_suite_from_id(0x1303), Some(CipherSuite::ChaCha20Poly1305Sha256));
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