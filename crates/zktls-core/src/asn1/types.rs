//! ASN.1 DER type definitions and tag constants
//!
//! This module defines the fundamental ASN.1 types needed for X.509 certificate
//! parsing according to ITU-T X.680/X.690 specifications.

use core::fmt;
use super::error::Asn1Result;

/// ASN.1 DER tag constants according to ITU-T X.690
pub mod tag {
    // Universal class tags (bits 7-6 = 00)
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const SEQUENCE: u8 = 0x30; // SEQUENCE OF / SEQUENCE (constructed)
    pub const SET: u8 = 0x31;     // SET OF / SET (constructed)
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const BOOLEAN: u8 = 0x01;
    pub const T61_STRING: u8 = 0x14;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    
    // Context-specific tags commonly used in X.509
    pub const CONTEXT_0: u8 = 0xA0;
    pub const CONTEXT_1: u8 = 0xA1;
    pub const CONTEXT_2: u8 = 0xA2;
    pub const CONTEXT_3: u8 = 0xA3;
}

/// ASN.1 length encoding limits for DER
pub const MAX_LENGTH_OCTETS: usize = 4; // Max 2^32 - 1 bytes
pub const MAX_SEQUENCE_DEPTH: usize = 32; // Prevent stack overflow

/// ASN.1 DER length encoding/decoding result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerLength {
    /// The actual length value
    pub value: usize,
    /// Number of bytes used to encode the length
    pub encoded_len: usize,
}

/// ASN.1 tag information parsed from DER
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerTag {
    /// Raw tag byte
    pub tag: u8,
    /// Whether this is a constructed type (has nested content)
    pub constructed: bool,
    /// Tag class (universal, application, context-specific, private)
    pub class: TagClass,
    /// Tag number within the class
    pub number: u32,
}

/// ASN.1 tag classes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl DerTag {
    /// Parse DER tag from byte
    pub fn from_byte(tag_byte: u8) -> Self {
        let constructed = (tag_byte & 0x20) != 0;
        let class = match (tag_byte & 0xC0) >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            3 => TagClass::Private,
            _ => unreachable!(),
        };
        let number = (tag_byte & 0x1F) as u32;
        
        Self {
            tag: tag_byte,
            constructed,
            class,
            number,
        }
    }
    
    /// Check if tag matches expected value
    pub fn matches(&self, expected_tag: u8) -> bool {
        self.tag == expected_tag
    }
}

/// ASN.1 DER value - the core parsing result
#[derive(Debug, Clone)]
pub struct DerValue<'a> {
    /// Parsed tag information
    pub tag: DerTag,
    /// Raw content bytes (without tag and length)
    pub content: &'a [u8],
    /// Total bytes consumed (tag + length + content)
    pub total_len: usize,
}

impl<'a> DerValue<'a> {
    /// Create new DER value
    pub fn new(tag: DerTag, content: &'a [u8], total_len: usize) -> Self {
        Self { tag, content, total_len }
    }
    
    /// Check if this value has expected tag
    pub fn expect_tag(&self, expected_tag: u8) -> Asn1Result<()> {
        if self.tag.matches(expected_tag) {
            Ok(())
        } else {
            Err(super::error::Asn1Error::UnexpectedTag {
                expected: expected_tag,
                found: self.tag.tag,
            })
        }
    }
}

impl fmt::Display for DerTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag(0x{:02X}, {:?})", self.tag, self.class)
    }
}