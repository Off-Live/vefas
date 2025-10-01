//! Input validation utilities for VEFAS crypto operations
//!
//! This module provides safe parsing utilities that can be shared across
//! different zkVM platforms. All parsing operations include comprehensive
//! bounds checking to prevent buffer overflows and ensure deterministic
//! behavior in zero-knowledge contexts.

use vefas_types::{VefasError, VefasResult};

/// Safe parser for bounds-checked binary data parsing
///
/// This parser ensures all read operations are bounds-checked and provides
/// deterministic behavior suitable for zero-knowledge proof contexts.
#[derive(Debug, Clone)]
pub struct SafeParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SafeParser<'a> {
    /// Create a new safe parser for the given data
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Get the number of bytes remaining to be read
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Check if we've reached the end of the data
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Get current offset position
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Read a single byte
    pub fn read_u8(&mut self) -> Option<u8> {
        if self.offset < self.data.len() {
            let value = self.data[self.offset];
            self.offset += 1;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 16-bit big-endian integer
    pub fn read_u16(&mut self) -> Option<u16> {
        if self.offset + 2 <= self.data.len() {
            let value = u16::from_be_bytes([self.data[self.offset], self.data[self.offset + 1]]);
            self.offset += 2;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 24-bit big-endian integer (returns as u32)
    pub fn read_u24(&mut self) -> Option<u32> {
        if self.offset + 3 <= self.data.len() {
            let value = ((self.data[self.offset] as u32) << 16)
                | ((self.data[self.offset + 1] as u32) << 8)
                | (self.data[self.offset + 2] as u32);
            self.offset += 3;
            Some(value)
        } else {
            None
        }
    }

    /// Read a 32-bit big-endian integer
    pub fn read_u32(&mut self) -> Option<u32> {
        if self.offset + 4 <= self.data.len() {
            let value = u32::from_be_bytes([
                self.data[self.offset],
                self.data[self.offset + 1],
                self.data[self.offset + 2],
                self.data[self.offset + 3],
            ]);
            self.offset += 4;
            Some(value)
        } else {
            None
        }
    }

    /// Read a slice of bytes
    ///
    /// Returns None if the requested length would exceed available data
    /// or if the length exceeds reasonable limits (65536 bytes) to prevent
    /// excessive memory allocation.
    pub fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        // Prevent excessive allocation
        if len > 65536 {
            return None;
        }

        if let Some(new_offset) = self.offset.checked_add(len) {
            if new_offset <= self.data.len() {
                let slice = &self.data[self.offset..new_offset];
                self.offset = new_offset;
                Some(slice)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Read a variable-length vector prefixed by a length field
    pub fn read_vec_u8(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u8()? as usize;
        self.read_bytes(len)
    }

    /// Read a variable-length vector prefixed by a 16-bit length field
    pub fn read_vec_u16(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u16()? as usize;
        self.read_bytes(len)
    }

    /// Read a variable-length vector prefixed by a 24-bit length field
    pub fn read_vec_u24(&mut self) -> Option<&'a [u8]> {
        let len = self.read_u24()? as usize;
        self.read_bytes(len)
    }

    /// Peek at the next byte without advancing the parser
    pub fn peek_u8(&self) -> Option<u8> {
        if self.offset < self.data.len() {
            Some(self.data[self.offset])
        } else {
            None
        }
    }

    /// Peek at the next 16-bit value without advancing the parser
    pub fn peek_u16(&self) -> Option<u16> {
        if self.offset + 2 <= self.data.len() {
            Some(u16::from_be_bytes([
                self.data[self.offset],
                self.data[self.offset + 1],
            ]))
        } else {
            None
        }
    }

    /// Skip a number of bytes
    pub fn skip(&mut self, len: usize) -> bool {
        if let Some(new_offset) = self.offset.checked_add(len) {
            if new_offset <= self.data.len() {
                self.offset = new_offset;
                return true;
            }
        }
        false
    }

    /// Get a slice of the remaining data without advancing the parser
    pub fn remaining_slice(&self) -> &'a [u8] {
        &self.data[self.offset..]
    }

    /// Reset the parser to the beginning
    pub fn reset(&mut self) {
        self.offset = 0;
    }

    /// Set the parser position to a specific offset
    pub fn seek(&mut self, offset: usize) -> bool {
        if offset <= self.data.len() {
            self.offset = offset;
            true
        } else {
            false
        }
    }
}

/// Parse DER length field with comprehensive validation
///
/// Returns (length, bytes_consumed) or None if invalid
pub fn parse_der_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first & 0x80 == 0 {
        // Short form: length fits in 7 bits
        Some((first as usize, 1))
    } else {
        // Long form: first byte indicates number of length bytes
        let length_bytes = (first & 0x7F) as usize;

        // Validate length encoding constraints
        if length_bytes == 0 || length_bytes > 4 || data.len() < 1 + length_bytes {
            return None;
        }

        // Parse multi-byte length
        let mut length = 0usize;
        for &byte in &data[1..1 + length_bytes] {
            length = match length.checked_mul(256) {
                Some(l) => match l.checked_add(byte as usize) {
                    Some(result) => result,
                    None => return None, // Overflow
                },
                None => return None, // Overflow
            };
        }

        // Sanity check: don't allow unreasonably large lengths
        if length > 0x1000000 {
            // 16MB limit
            return None;
        }

        Some((length, 1 + length_bytes))
    }
}

/// Parse 24-bit length field with overflow protection
pub fn parse_24bit_length(data: &[u8]) -> Option<usize> {
    if data.len() < 3 {
        return None;
    }

    let len = ((data[0] as usize) << 16) | ((data[1] as usize) << 8) | (data[2] as usize);

    // Sanity check - 24-bit length should not exceed reasonable limits for TLS
    if len > 0xFFFF {
        return None;
    }

    Some(len)
}

/// Validate TLS record header structure
pub fn validate_tls_record_header(data: &[u8]) -> VefasResult<(u8, u16, usize)> {
    if data.len() < 5 {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Record too short (minimum 5 bytes)",
        ));
    }

    if data.len() > 16389 {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Record too long (maximum 16389 bytes)",
        ));
    }

    let content_type = data[0];
    let version = u16::from_be_bytes([data[1], data[2]]);
    let declared_len = u16::from_be_bytes([data[3], data[4]]) as usize;

    // Validate content type
    match content_type {
        20 | 21 | 22 | 23 => {} // change_cipher_spec, alert, handshake, application_data
        _ => {
            return Err(VefasError::invalid_input(
                "tls_record",
                "Invalid content type",
            ))
        }
    }

    // Validate TLS version
    match version {
        0x0303 => {} // TLS 1.2 (used in TLS 1.3 records for compatibility)
        _ => {
            return Err(VefasError::invalid_input(
                "tls_record",
                "Unsupported TLS version",
            ))
        }
    }

    // Validate declared length
    if declared_len == 0 {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Zero-length record",
        ));
    }

    if declared_len > 16384 {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Record payload too large",
        ));
    }

    if 5 + declared_len != data.len() {
        return Err(VefasError::invalid_input(
            "tls_record",
            "Record length mismatch",
        ));
    }

    Ok((content_type, version, declared_len))
}

/// Validate handshake message header
pub fn validate_handshake_header(data: &[u8]) -> VefasResult<(u8, usize)> {
    if data.len() < 4 {
        return Err(VefasError::invalid_input(
            "handshake",
            "Handshake message too short",
        ));
    }

    let msg_type = data[0];
    let declared_len = parse_24bit_length(&data[1..4])
        .ok_or_else(|| VefasError::invalid_input("handshake", "Invalid length encoding"))?;

    // Validate handshake message type
    match msg_type {
        0x01 | 0x02 | 0x0b | 0x0f | 0x14 => {} // Valid types: ClientHello, ServerHello, Certificate, CertificateVerify, Finished
        _ => {
            return Err(VefasError::invalid_input(
                "handshake",
                "Invalid handshake message type",
            ))
        }
    }

    // Validate declared length matches available data
    if 4 + declared_len > data.len() {
        return Err(VefasError::invalid_input(
            "handshake",
            "Handshake message length exceeds available data",
        ));
    }

    // Validate length is reasonable (prevent DoS)
    if declared_len > 32768 {
        return Err(VefasError::invalid_input(
            "handshake",
            "Handshake message too large",
        ));
    }

    Ok((msg_type, declared_len))
}

/// Memory search implementation (memmem) for certificate domain matching
pub fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }

    let last = haystack.len() - needle.len();
    let first = needle[0];
    let rest = &needle[1..];

    for i in 0..=last {
        if haystack[i] == first && haystack[i + 1..i + 1 + rest.len()] == *rest {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_parser_bounds_checking() {
        let data = [1, 2, 3, 4, 5];
        let mut parser = SafeParser::new(&data);

        // Normal operations
        assert_eq!(parser.read_u8(), Some(1));
        assert_eq!(parser.read_u16(), Some(0x0203));
        assert_eq!(parser.read_bytes(2), Some(&[4, 5][..]));

        // Out of bounds
        assert_eq!(parser.read_u8(), None);
        assert_eq!(parser.read_u16(), None);
    }

    #[test]
    fn safe_parser_prevents_excessive_allocation() {
        let data = [1, 2, 3, 4, 5];
        let mut parser = SafeParser::new(&data);

        // Try to read more than 65536 bytes
        assert_eq!(parser.read_bytes(70000), None);
    }

    #[test]
    fn safe_parser_24bit_operations() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut parser = SafeParser::new(&data);

        assert_eq!(parser.read_u24(), Some(0x010203));
        assert_eq!(parser.read_u8(), Some(0x04));
        assert_eq!(parser.read_u8(), None);
    }

    #[test]
    fn parse_der_length_short_form() {
        let data = [0x05, 0x01, 0x02];
        assert_eq!(parse_der_length(&data), Some((5, 1)));
    }

    #[test]
    fn parse_der_length_long_form() {
        let data = [0x82, 0x01, 0x00, 0xFF]; // Length 256 in long form
        assert_eq!(parse_der_length(&data), Some((256, 3)));
    }

    #[test]
    fn parse_der_length_invalid() {
        // Invalid: indefinite length (0x80)
        let data = [0x80];
        assert_eq!(parse_der_length(&data), None);

        // Invalid: too many length bytes
        let data = [0x85, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(parse_der_length(&data), None);
    }

    #[test]
    fn parse_24bit_length_valid() {
        let data = [0x00, 0x02, 0x03];
        assert_eq!(parse_24bit_length(&data), Some(0x000203)); // 515 in decimal, within 0xFFFF limit
    }

    #[test]
    fn parse_24bit_length_too_large() {
        let data = [0xFF, 0xFF, 0xFF];
        assert_eq!(parse_24bit_length(&data), None);
    }

    #[test]
    fn validate_tls_record_valid() {
        let record = [23, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let result = validate_tls_record_header(&record);
        assert!(result.is_ok());
        let (content_type, version, len) = result.unwrap();
        assert_eq!(content_type, 23);
        assert_eq!(version, 0x0303);
        assert_eq!(len, 5);
    }

    #[test]
    fn validate_tls_record_invalid_type() {
        let record = [99, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let result = validate_tls_record_header(&record);
        assert!(result.is_err());
    }

    #[test]
    fn validate_handshake_header_valid() {
        let handshake = [0x01, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5];
        let result = validate_handshake_header(&handshake);
        assert!(result.is_ok());
        let (msg_type, len) = result.unwrap();
        assert_eq!(msg_type, 0x01);
        assert_eq!(len, 5);
    }

    #[test]
    fn validate_handshake_header_invalid_type() {
        let handshake = [0xFF, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5];
        let result = validate_handshake_header(&handshake);
        assert!(result.is_err());
    }

    #[test]
    fn memmem_finds_needle() {
        let haystack = b"hello world";
        let needle = b"world";
        assert!(memmem(haystack, needle));
    }

    #[test]
    fn memmem_doesnt_find_missing_needle() {
        let haystack = b"hello world";
        let needle = b"xyz";
        assert!(!memmem(haystack, needle));
    }

    #[test]
    fn memmem_empty_needle() {
        let haystack = b"hello world";
        let needle = b"";
        assert!(memmem(haystack, needle));
    }
}
