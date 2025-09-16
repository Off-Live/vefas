//! ASN.1 DER parsing errors
//!
//! Comprehensive error types for ASN.1 DER parsing with detailed context
//! to aid in debugging certificate parsing issues.

use core::fmt;

/// ASN.1 DER parsing errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Asn1Error {
    /// Input data too short to contain valid DER structure
    UnexpectedEof,
    
    /// Invalid DER tag byte
    InvalidTag(u8),
    
    /// Invalid length encoding
    InvalidLength,
    
    /// Length exceeds available data
    InsufficientData { expected: usize, available: usize },
    
    /// BER indefinite length encoding (not allowed in DER)
    IndefiniteLength,
    
    /// Length encoding is not minimal (DER violation)
    NonMinimalLength,
    
    /// Maximum nesting depth exceeded
    MaxDepthExceeded,
    
    /// Invalid INTEGER encoding (leading zeros, empty)
    InvalidInteger,
    
    /// Invalid BIT STRING encoding
    InvalidBitString,
    
    /// Invalid OBJECT IDENTIFIER encoding
    InvalidOid,
    
    /// Unexpected tag (expected different type)
    UnexpectedTag { expected: u8, found: u8 },
    
    /// Invalid UTF-8 in string types
    InvalidUtf8,
    
    /// Generic parsing error with context
    ParseError(&'static str),
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asn1Error::UnexpectedEof => write!(f, "Unexpected end of input"),
            Asn1Error::InvalidTag(tag) => write!(f, "Invalid DER tag: 0x{:02x}", tag),
            Asn1Error::InvalidLength => write!(f, "Invalid length encoding"),
            Asn1Error::InsufficientData { expected, available } => {
                write!(f, "Insufficient data: expected {}, got {}", expected, available)
            }
            Asn1Error::IndefiniteLength => write!(f, "Indefinite length not allowed in DER"),
            Asn1Error::NonMinimalLength => write!(f, "Length encoding not minimal (DER violation)"),
            Asn1Error::MaxDepthExceeded => write!(f, "Maximum nesting depth exceeded"),
            Asn1Error::InvalidInteger => write!(f, "Invalid INTEGER encoding"),
            Asn1Error::InvalidBitString => write!(f, "Invalid BIT STRING encoding"),
            Asn1Error::InvalidOid => write!(f, "Invalid OBJECT IDENTIFIER encoding"),
            Asn1Error::UnexpectedTag { expected, found } => {
                write!(f, "Unexpected tag: expected 0x{:02x}, found 0x{:02x}", expected, found)
            }
            Asn1Error::InvalidUtf8 => write!(f, "Invalid UTF-8 in string"),
            Asn1Error::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

pub type Asn1Result<T> = Result<T, Asn1Error>;