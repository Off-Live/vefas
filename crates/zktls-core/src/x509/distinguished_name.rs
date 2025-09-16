//! Distinguished Name (DN) parsing for X.509 certificates
//!
//! This module implements Distinguished Name parsing according to RFC 5280.
//! Distinguished Names are used for certificate issuer and subject identification.

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec, format};
use crate::asn1::{DerParser, DerValue, tag};
use super::{X509Error, X509Result};

/// Distinguished Name representation
/// 
/// Based on RFC 5280 Name structure:
/// ```asn1
/// Name ::= CHOICE { -- only one possibility for now --
///   rdnSequence  RDNSequence }
/// 
/// RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
/// 
/// RelativeDistinguishedName ::=
///   SET SIZE (1..MAX) OF AttributeTypeAndValue
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct DistinguishedName<'a> {
    /// Raw DN data for verification
    raw_data: &'a [u8],
    
    /// Parsed attributes
    attributes: Vec<AttributeTypeAndValue>,
}

/// Attribute Type and Value pair
#[derive(Debug, Clone, PartialEq)]
pub struct AttributeTypeAndValue {
    /// Attribute type OID
    attribute_type: String,
    
    /// Attribute value
    attribute_value: String,
}

impl<'a> DistinguishedName<'a> {
    /// Parse a Distinguished Name from ASN.1 DER
    pub fn parse(dn_value: &DerValue<'a>) -> X509Result<Self> {
        if !dn_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidDistinguishedName);
        }
        
        let mut attributes = Vec::new();
        let mut rdn_iter = DerParser::parse_sequence(dn_value.content, 1)?;
        
        // Parse each RelativeDistinguishedName
        while let Some(rdn_result) = rdn_iter.next() {
            let rdn = rdn_result?;
            
            if !rdn.tag.matches(tag::SET) {
                return Err(X509Error::InvalidDistinguishedName);
            }
            
            // Parse AttributeTypeAndValue within the SET
            let mut attr_iter = DerParser::parse_sequence(rdn.content, 2)?;
            
            while let Some(attr_result) = attr_iter.next() {
                let attr = attr_result?;
                let attribute = Self::parse_attribute_type_and_value(&attr)?;
                attributes.push(attribute);
            }
        }
        
        Ok(DistinguishedName {
            raw_data: dn_value.content,
            attributes,
        })
    }
    
    /// Parse an AttributeTypeAndValue structure
    fn parse_attribute_type_and_value(attr_value: &DerValue) -> X509Result<AttributeTypeAndValue> {
        if !attr_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidDistinguishedName);
        }
        
        let mut seq_iter = DerParser::parse_sequence(attr_value.content, 1)?;
        
        // Parse attribute type (OID)
        let type_item = seq_iter.next()
            .ok_or(X509Error::InvalidDistinguishedName)??;
            
        if !type_item.tag.matches(tag::OBJECT_IDENTIFIER) {
            return Err(X509Error::InvalidDistinguishedName);
        }
        
        let oid_components = DerParser::parse_oid(type_item.content)?;
        let oid_string = oid_components.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(".");
        
        // Parse attribute value
        let value_item = seq_iter.next()
            .ok_or(X509Error::InvalidDistinguishedName)??;
            
        let attribute_value = Self::parse_directory_string(&value_item)?;
        
        Ok(AttributeTypeAndValue {
            attribute_type: oid_string,
            attribute_value,
        })
    }
    
    /// Parse DirectoryString (various string types)
    fn parse_directory_string(value_item: &DerValue) -> X509Result<String> {
        let string_data = if value_item.tag.matches(tag::UTF8_STRING) {
            // UTF8String
            core::str::from_utf8(value_item.content)
                .map_err(|_| X509Error::InvalidDistinguishedName)?
                .to_string()
        } else if value_item.tag.matches(tag::PRINTABLE_STRING) {
            // PrintableString (ASCII subset)
            Self::parse_printable_string(value_item.content)?
        } else if value_item.tag.matches(tag::IA5_STRING) {
            // IA5String (ASCII)
            core::str::from_utf8(value_item.content)
                .map_err(|_| X509Error::InvalidDistinguishedName)?
                .to_string()
        } else {
            // For now, treat unknown string types as raw bytes
            // In production, should support BMPString, UniversalString, etc.
            String::from_utf8_lossy(value_item.content).to_string()
        };
        
        Ok(string_data)
    }
    
    /// Parse PrintableString (restricted ASCII character set)
    fn parse_printable_string(data: &[u8]) -> X509Result<String> {
        // PrintableString allows: A-Z, a-z, 0-9, space, and some punctuation
        for &byte in data {
            let is_valid = matches!(byte, 
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | 
                b' ' | b'\'' | b'(' | b')' | b'+' | b',' | 
                b'-' | b'.' | b'/' | b':' | b'=' | b'?'
            );
            
            if !is_valid {
                return Err(X509Error::InvalidDistinguishedName);
            }
        }
        
        Ok(String::from_utf8(data.to_vec())
            .map_err(|_| X509Error::InvalidDistinguishedName)?)
    }
    
    /// Get the Common Name (CN) attribute
    pub fn common_name(&self) -> Option<&str> {
        self.get_attribute_value("2.5.4.3") // CN OID
    }
    
    /// Get the Organization (O) attribute
    pub fn organization(&self) -> Option<&str> {
        self.get_attribute_value("2.5.4.10") // O OID
    }
    
    /// Get the Country (C) attribute
    pub fn country(&self) -> Option<&str> {
        self.get_attribute_value("2.5.4.6") // C OID
    }
    
    /// Get the Organizational Unit (OU) attribute
    pub fn organizational_unit(&self) -> Option<&str> {
        self.get_attribute_value("2.5.4.11") // OU OID
    }
    
    /// Get attribute value by OID
    fn get_attribute_value(&self, oid: &str) -> Option<&str> {
        self.attributes.iter()
            .find(|attr| attr.attribute_type == oid)
            .map(|attr| attr.attribute_value.as_str())
    }
    
    /// Get all attributes
    pub fn attributes(&self) -> &[AttributeTypeAndValue] {
        &self.attributes
    }
    
    /// Get raw DN data
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
}

impl<'a> ToString for DistinguishedName<'a> {
    fn to_string(&self) -> String {
        if self.attributes.is_empty() {
            return String::new();
        }
        
        // Format as comma-separated attribute=value pairs
        self.attributes.iter()
            .map(|attr| {
                // Convert common OIDs to readable names
                let name = match attr.attribute_type.as_str() {
                    "2.5.4.3" => "CN",      // Common Name
                    "2.5.4.10" => "O",     // Organization
                    "2.5.4.11" => "OU",    // Organizational Unit  
                    "2.5.4.6" => "C",      // Country
                    "2.5.4.7" => "L",      // Locality
                    "2.5.4.8" => "ST",     // State/Province
                    "1.2.840.113549.1.9.1" => "emailAddress", // Email
                    _ => &attr.attribute_type, // Use OID if unknown
                };
                format!("{}={}", name, attr.attribute_value)
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl AttributeTypeAndValue {
    /// Get attribute type OID
    pub fn attribute_type(&self) -> &str {
        &self.attribute_type
    }
    
    /// Get attribute value
    pub fn attribute_value(&self) -> &str {
        &self.attribute_value
    }
}