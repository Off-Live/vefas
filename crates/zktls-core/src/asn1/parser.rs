//! ASN.1 DER parser implementation
//!
//! This module provides the core DER parsing functionality for X.509 certificates.
//! It implements strict DER validation according to ITU-T X.690.

use alloc::vec::Vec;
use super::error::{Asn1Error, Asn1Result};
use super::types::{DerValue, DerTag, DerLength, MAX_LENGTH_OCTETS, MAX_SEQUENCE_DEPTH};

/// ASN.1 DER parser with strict validation
pub struct DerParser;

impl DerParser {
    /// Parse a single DER value from input bytes
    /// 
    /// # Arguments
    /// * `input` - DER-encoded bytes to parse
    /// * `depth` - Current nesting depth (for recursion limit)
    /// 
    /// # Returns
    /// * `Ok((remaining, value))` - Remaining bytes and parsed DER value
    /// * `Err(Asn1Error)` - Parsing error with details
    pub fn parse_value(input: &[u8], depth: usize) -> Asn1Result<(&[u8], DerValue)> {
        if depth >= MAX_SEQUENCE_DEPTH {
            return Err(Asn1Error::MaxDepthExceeded);
        }
        
        if input.is_empty() {
            return Err(Asn1Error::UnexpectedEof);
        }
        
        // Parse tag
        let tag_byte = input[0];
        let tag = DerTag::from_byte(tag_byte);
        
        // Parse length
        let (remaining_after_length, length_info) = Self::parse_length(&input[1..])?;
        
        // Check if we have enough data for the content
        if remaining_after_length.len() < length_info.value {
            return Err(Asn1Error::InsufficientData {
                expected: length_info.value,
                available: remaining_after_length.len(),
            });
        }
        
        // Extract content and remaining bytes
        let content = &remaining_after_length[..length_info.value];
        let remaining = &remaining_after_length[length_info.value..];
        
        // Calculate total consumed bytes
        let total_len = 1 + length_info.encoded_len + length_info.value;
        
        // Create DER value
        let der_value = DerValue::new(tag, content, total_len);
        
        Ok((remaining, der_value))
    }
    
    /// Parse DER length encoding
    /// 
    /// DER uses definite length encoding only:
    /// - Short form: length < 128 (0x80), encoded as single byte
    /// - Long form: length >= 128, first byte = 0x80 + number of length bytes
    /// 
    /// # Arguments
    /// * `input` - Bytes starting with length encoding
    /// 
    /// # Returns
    /// * `Ok((remaining, length))` - Remaining bytes and parsed length info
    pub fn parse_length(input: &[u8]) -> Asn1Result<(&[u8], DerLength)> {
        if input.is_empty() {
            return Err(Asn1Error::UnexpectedEof);
        }

        let first_byte = input[0];
        
        if first_byte == 0x80 {
            // Indefinite length (not allowed in DER)
            return Err(Asn1Error::IndefiniteLength);
        }
        
        if first_byte < 0x80 {
            // Short form: length is encoded in the first byte
            let length = first_byte as usize;
            let remaining = &input[1..];
            Ok((remaining, DerLength {
                value: length,
                encoded_len: 1,
            }))
        } else {
            // Long form: first byte indicates number of length bytes
            let num_octets = (first_byte & 0x7F) as usize;
            
            if num_octets == 0 {
                // This is the indefinite length case (0x80), already handled above
                return Err(Asn1Error::IndefiniteLength);
            }
            
            if num_octets > MAX_LENGTH_OCTETS {
                return Err(Asn1Error::InvalidLength);
            }
            
            if input.len() < 1 + num_octets {
                return Err(Asn1Error::UnexpectedEof);
            }
            
            // Parse the length value from the following bytes
            let mut length = 0usize;
            let length_bytes = &input[1..1 + num_octets];
            
            // Check for non-minimal encoding (DER violation)
            // Leading byte must not be zero (except for length 0, but that would be short form)
            if length_bytes[0] == 0 {
                return Err(Asn1Error::NonMinimalLength);
            }
            
            for &byte in length_bytes {
                length = length.checked_shl(8)
                    .and_then(|l| l.checked_add(byte as usize))
                    .ok_or(Asn1Error::InvalidLength)?;
            }
            
            // Check if this should have been encoded in short form
            if length < 128 {
                return Err(Asn1Error::NonMinimalLength);
            }
            
            let remaining = &input[1 + num_octets..];
            Ok((remaining, DerLength {
                value: length,
                encoded_len: 1 + num_octets,
            }))
        }
    }
    
    /// Parse INTEGER value with DER validation
    /// 
    /// DER INTEGER rules:
    /// - Must not have unnecessary leading zeros
    /// - Must not be empty
    /// - Must be two's complement encoding
    pub fn parse_integer(content: &[u8]) -> Asn1Result<&[u8]> {
        if content.is_empty() {
            return Err(Asn1Error::InvalidInteger);
        }
        
        // Check for unnecessary leading zeros
        if content.len() > 1 && content[0] == 0x00 {
            // Leading zero is only allowed if the next byte would be interpreted as negative
            if content[1] & 0x80 == 0 {
                return Err(Asn1Error::InvalidInteger);
            }
        }
        
        Ok(content)
    }
    
    /// Parse BIT STRING value with DER validation
    /// 
    /// DER BIT STRING rules:
    /// - First byte indicates number of unused bits (0-7)
    /// - If unused bits > 0, trailing bits must be zero
    pub fn parse_bit_string(content: &[u8]) -> Asn1Result<(&[u8], u8)> {
        if content.is_empty() {
            return Err(Asn1Error::InvalidBitString);
        }
        
        let unused_bits = content[0];
        
        // Unused bits must be in range 0-7
        if unused_bits > 7 {
            return Err(Asn1Error::InvalidBitString);
        }
        
        let data = &content[1..];
        
        // If there are unused bits, verify trailing bits are zero
        if unused_bits > 0 && !data.is_empty() {
            let last_byte = data[data.len() - 1];
            let mask = (1u8 << unused_bits) - 1; // Create mask for unused bits
            
            if last_byte & mask != 0 {
                return Err(Asn1Error::InvalidBitString);
            }
        }
        
        Ok((data, unused_bits))
    }
    
    /// Parse OBJECT IDENTIFIER value with validation
    /// 
    /// OID encoding rules:
    /// - First byte encodes first two components: 40*first + second
    /// - Remaining components use variable-length encoding
    /// - Each component uses base-128 with continuation bit
    pub fn parse_oid(content: &[u8]) -> Asn1Result<Vec<u32>> {
        if content.is_empty() {
            return Err(Asn1Error::InvalidOid);
        }
        
        let mut components = Vec::new();
        let mut pos = 0;
        
        // Decode the first two components from the first byte
        let first_byte = content[0];
        let first_component = first_byte / 40;
        let second_component = first_byte % 40;
        components.push(first_component as u32);
        components.push(second_component as u32);
        pos += 1;
        
        // Decode remaining components using variable-length encoding
        while pos < content.len() {
            let mut value = 0u32;
            
            loop {
                if pos >= content.len() {
                    return Err(Asn1Error::InvalidOid);
                }
                
                let byte = content[pos];
                pos += 1;
                
                // Check for overflow
                if value > (u32::MAX >> 7) {
                    return Err(Asn1Error::InvalidOid);
                }
                
                value = (value << 7) | ((byte & 0x7F) as u32);
                
                // If continuation bit is not set, this component is complete
                if byte & 0x80 == 0 {
                    break;
                }
            }
            
            components.push(value);
        }
        
        Ok(components)
    }
    
    /// Parse SEQUENCE and return iterator over contained values
    /// 
    /// # Arguments
    /// * `content` - SEQUENCE content bytes (without SEQUENCE tag/length)
    /// * `depth` - Current nesting depth
    pub fn parse_sequence(content: &[u8], depth: usize) -> Asn1Result<SequenceIter> {
        Ok(SequenceIter {
            remaining: content,
            depth,
        })
    }
}

/// Iterator over SEQUENCE contents
pub struct SequenceIter<'a> {
    remaining: &'a [u8],
    depth: usize,
}

impl<'a> Iterator for SequenceIter<'a> {
    type Item = Asn1Result<DerValue<'a>>;
    
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        
        match DerParser::parse_value(self.remaining, self.depth + 1) {
            Ok((remaining, value)) => {
                self.remaining = remaining;
                Some(Ok(value))
            }
            Err(e) => {
                // Clear remaining to prevent further iteration after error
                self.remaining = &[];
                Some(Err(e))
            }
        }
    }
}