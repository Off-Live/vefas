//! X.509 certificate extensions parsing
//!
//! This module implements certificate extension parsing according to RFC 5280.
//! Focuses on critical extensions needed for TLS validation.

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec};
use crate::asn1::{DerParser, DerValue, tag};
use super::{X509Error, X509Result};

/// Certificate extension
/// 
/// Based on RFC 5280 Extension structure:
/// ```asn1
/// Extension  ::=  SEQUENCE  {
///      extnID      OBJECT IDENTIFIER,
///      critical    BOOLEAN DEFAULT FALSE,
///      extnValue   OCTET STRING
///                  -- contains the DER encoding of an ASN.1 value
///                  -- corresponding to the extension type identified
///                  -- by extnID
///      }
/// ```
#[derive(Debug, Clone)]
pub struct Extension<'a> {
    /// Extension OID
    extension_id: String,
    
    /// Whether extension is critical
    critical: bool,
    
    /// Extension value (DER-encoded)
    value: &'a [u8],
    
    /// Parsed extension type
    extension_type: ExtensionType<'a>,
}

/// Supported extension types
#[derive(Debug, Clone)]
pub enum ExtensionType<'a> {
    /// Basic Constraints (2.5.29.19)
    BasicConstraints(BasicConstraints),
    
    /// Key Usage (2.5.29.15)
    KeyUsage(KeyUsage),
    
    /// Extended Key Usage (2.5.29.37)
    ExtendedKeyUsage(ExtendedKeyUsage),
    
    /// Subject Alternative Name (2.5.29.17)
    SubjectAltName(SubjectAltName<'a>),
    
    /// Subject Key Identifier (2.5.29.14)
    SubjectKeyIdentifier(&'a [u8]),
    
    /// Authority Key Identifier (2.5.29.35)
    AuthorityKeyIdentifier(AuthorityKeyIdentifier<'a>),
    
    /// Unknown extension
    Unknown {
        oid: String,
        data: &'a [u8],
    },
}

/// Basic Constraints extension
#[derive(Debug, Clone)]
pub struct BasicConstraints {
    /// Whether this is a CA certificate
    ca: bool,
    
    /// Path length constraint (None = unlimited)
    path_len_constraint: Option<u32>,
    
    /// Whether extension is critical
    critical: bool,
}

/// Key Usage extension
#[derive(Debug, Clone)]
pub struct KeyUsage {
    /// Key usage flags
    flags: u16,
    
    /// Whether extension is critical
    critical: bool,
}

/// Extended Key Usage extension
#[derive(Debug, Clone)]
pub struct ExtendedKeyUsage {
    /// Key purpose OIDs
    key_purposes: Vec<String>,
    
    /// Whether extension is critical
    critical: bool,
}

/// Subject Alternative Name extension
#[derive(Debug, Clone)]
pub struct SubjectAltName<'a> {
    /// Alternative names
    names: Vec<GeneralName<'a>>,
    
    /// Whether extension is critical
    critical: bool,
}

/// Authority Key Identifier extension
#[derive(Debug, Clone)]
pub struct AuthorityKeyIdentifier<'a> {
    /// Key identifier
    key_identifier: Option<&'a [u8]>,
    
    /// Authority cert issuer (not implemented)
    authority_cert_issuer: Option<()>,
    
    /// Authority cert serial number (not implemented)
    authority_cert_serial: Option<()>,
    
    /// Whether extension is critical
    critical: bool,
}

/// General Name for Subject Alternative Name
#[derive(Debug, Clone)]
pub enum GeneralName<'a> {
    /// DNS name
    DnsName(&'a str),
    
    /// IP address
    IpAddress(&'a [u8]),
    
    /// Email address
    Rfc822Name(&'a str),
    
    /// URI
    UniformResourceIdentifier(&'a str),
    
    /// Other name types (not fully implemented)
    Other {
        tag: u8,
        data: &'a [u8],
    },
}

impl<'a> Extension<'a> {
    /// Parse certificate extension from ASN.1 DER
    pub fn parse(ext_value: &DerValue<'a>) -> X509Result<Self> {
        if !ext_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut seq_iter = DerParser::parse_sequence(ext_value.content, 1)?;
        
        // Parse extension ID (OID)
        let id_item = seq_iter.next()
            .ok_or(X509Error::InvalidExtension)??;
            
        if !id_item.tag.matches(tag::OBJECT_IDENTIFIER) {
            return Err(X509Error::InvalidExtension);
        }
        
        let oid_components = DerParser::parse_oid(id_item.content)?;
        let extension_id = oid_components.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(".");
        
        // Parse optional critical flag
        let (critical, value_item) = match seq_iter.next() {
            Some(Ok(item)) => {
                if item.tag.matches(tag::BOOLEAN) {
                    // Critical flag is present
                    let critical_flag = item.content;
                    if critical_flag.len() != 1 {
                        return Err(X509Error::InvalidExtension);
                    }
                    let critical = critical_flag[0] != 0;
                    
                    // Get extension value
                    let value_item = seq_iter.next()
                        .ok_or(X509Error::InvalidExtension)??;
                    
                    (critical, value_item)
                } else {
                    // No critical flag, defaults to false
                    (false, item)
                }
            },
            Some(Err(e)) => return Err(e.into()),
            None => return Err(X509Error::InvalidExtension),
        };
        
        // Extension value should be OCTET STRING
        if !value_item.tag.matches(tag::OCTET_STRING) {
            return Err(X509Error::InvalidExtension);
        }
        
        let value = value_item.content;
        
        // Parse specific extension type
        let extension_type = Self::parse_extension_type(&extension_id, value, critical)?;
        
        Ok(Extension {
            extension_id,
            critical,
            value,
            extension_type,
        })
    }
    
    /// Parse specific extension type based on OID
    fn parse_extension_type(oid: &str, value: &'a [u8], critical: bool) -> X509Result<ExtensionType<'a>> {
        match oid {
            "2.5.29.19" => {
                // Basic Constraints
                let basic_constraints = BasicConstraints::parse(value, critical)?;
                Ok(ExtensionType::BasicConstraints(basic_constraints))
            },
            "2.5.29.15" => {
                // Key Usage
                let key_usage = KeyUsage::parse(value, critical)?;
                Ok(ExtensionType::KeyUsage(key_usage))
            },
            "2.5.29.37" => {
                // Extended Key Usage
                let ext_key_usage = ExtendedKeyUsage::parse(value, critical)?;
                Ok(ExtensionType::ExtendedKeyUsage(ext_key_usage))
            },
            "2.5.29.17" => {
                // Subject Alternative Name
                let subject_alt_name = SubjectAltName::parse(value, critical)?;
                Ok(ExtensionType::SubjectAltName(subject_alt_name))
            },
            "2.5.29.14" => {
                // Subject Key Identifier
                Ok(ExtensionType::SubjectKeyIdentifier(value))
            },
            "2.5.29.35" => {
                // Authority Key Identifier
                let auth_key_id = AuthorityKeyIdentifier::parse(value, critical)?;
                Ok(ExtensionType::AuthorityKeyIdentifier(auth_key_id))
            },
            _ => {
                // Unknown extension
                Ok(ExtensionType::Unknown {
                    oid: oid.to_string(),
                    data: value,
                })
            }
        }
    }
    
    /// Get extension ID (OID)
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
    
    /// Get extension value
    pub fn value(&self) -> &[u8] {
        self.value
    }
    
    /// Get parsed extension type
    pub fn extension_type(&self) -> &ExtensionType {
        &self.extension_type
    }
}

impl BasicConstraints {
    /// Parse Basic Constraints extension
    fn parse(value: &[u8], critical: bool) -> X509Result<Self> {
        // Basic Constraints value is a DER-encoded SEQUENCE
        let (_, constraints_seq) = DerParser::parse_value(value, 0)?;
        
        if !constraints_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut ca = false;
        let mut path_len_constraint = None;
        
        let mut seq_iter = DerParser::parse_sequence(constraints_seq.content, 1)?;
        
        // Parse optional cA BOOLEAN
        if let Some(item_result) = seq_iter.next() {
            let item = item_result?;
            
            if item.tag.matches(tag::BOOLEAN) {
                let ca_flag = item.content;
                if ca_flag.len() != 1 {
                    return Err(X509Error::InvalidExtension);
                }
                ca = ca_flag[0] != 0;
                
                // Parse optional pathLenConstraint
                if let Some(path_result) = seq_iter.next() {
                    let path_item = path_result?;
                    
                    if path_item.tag.matches(tag::INTEGER) {
                        let path_len_bytes = DerParser::parse_integer(path_item.content)?;
                        
                        // Convert to u32 (simplified)
                        let mut path_len = 0u32;
                        for &byte in path_len_bytes.iter().take(4) {
                            path_len = (path_len << 8) | (byte as u32);
                        }
                        
                        path_len_constraint = Some(path_len);
                    }
                }
            }
        }
        
        Ok(BasicConstraints {
            ca,
            path_len_constraint,
            critical,
        })
    }
    
    /// Check if this is a CA certificate
    pub fn is_ca(&self) -> bool {
        self.ca
    }
    
    /// Get path length constraint
    pub fn path_len_constraint(&self) -> Option<u32> {
        self.path_len_constraint
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
}

impl KeyUsage {
    /// Parse Key Usage extension
    fn parse(value: &[u8], critical: bool) -> X509Result<Self> {
        // Key Usage value is a DER-encoded BIT STRING
        let (_, key_usage_bits) = DerParser::parse_value(value, 0)?;
        
        if !key_usage_bits.tag.matches(tag::BIT_STRING) {
            return Err(X509Error::InvalidExtension);
        }
        
        let (bits_data, _unused_bits) = DerParser::parse_bit_string(key_usage_bits.content)?;
        
        // Convert bit string to flags
        let mut flags = 0u16;
        for (i, &byte) in bits_data.iter().enumerate() {
            if i >= 2 { break; } // Only use first 16 bits
            flags |= (byte as u16) << (8 * (1 - i));
        }
        
        Ok(KeyUsage {
            flags,
            critical,
        })
    }
    
    /// Get key usage flags
    pub fn flags(&self) -> u16 {
        self.flags
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
}

impl ExtendedKeyUsage {
    /// Parse Extended Key Usage extension
    fn parse(value: &[u8], critical: bool) -> X509Result<Self> {
        // Extended Key Usage value is a DER-encoded SEQUENCE OF OBJECT IDENTIFIER
        let (_, eku_seq) = DerParser::parse_value(value, 0)?;
        
        if !eku_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut key_purposes = Vec::new();
        let mut seq_iter = DerParser::parse_sequence(eku_seq.content, 1)?;
        
        while let Some(oid_result) = seq_iter.next() {
            let oid_item = oid_result?;
            
            if !oid_item.tag.matches(tag::OBJECT_IDENTIFIER) {
                return Err(X509Error::InvalidExtension);
            }
            
            let oid_components = DerParser::parse_oid(oid_item.content)?;
            let oid_string = oid_components.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(".");
                
            key_purposes.push(oid_string);
        }
        
        Ok(ExtendedKeyUsage {
            key_purposes,
            critical,
        })
    }
    
    /// Get key purpose OIDs
    pub fn key_purposes(&self) -> &[String] {
        &self.key_purposes
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
}

impl<'a> SubjectAltName<'a> {
    /// Parse Subject Alternative Name extension
    fn parse(value: &'a [u8], critical: bool) -> X509Result<Self> {
        // SAN value is a DER-encoded SEQUENCE OF GeneralName
        let (_, san_seq) = DerParser::parse_value(value, 0)?;
        
        if !san_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut names = Vec::new();
        let mut seq_iter = DerParser::parse_sequence(san_seq.content, 1)?;
        
        while let Some(name_result) = seq_iter.next() {
            let name_item = name_result?;
            let general_name = GeneralName::parse(&name_item)?;
            names.push(general_name);
        }
        
        Ok(SubjectAltName {
            names,
            critical,
        })
    }
    
    /// Get alternative names
    pub fn names(&self) -> &[GeneralName] {
        &self.names
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
}

impl<'a> GeneralName<'a> {
    /// Parse GeneralName
    fn parse(name_item: &DerValue<'a>) -> X509Result<Self> {
        // GeneralName uses context-specific tags
        let tag_number = name_item.tag.number;
        let name_data = name_item.content;
        
        match tag_number {
            2 => {
                // dNSName [2] IA5String
                let dns_name = core::str::from_utf8(name_data)
                    .map_err(|_| X509Error::InvalidExtension)?;
                Ok(GeneralName::DnsName(dns_name))
            },
            7 => {
                // iPAddress [7] OCTET STRING
                Ok(GeneralName::IpAddress(name_data))
            },
            1 => {
                // rfc822Name [1] IA5String
                let email = core::str::from_utf8(name_data)
                    .map_err(|_| X509Error::InvalidExtension)?;
                Ok(GeneralName::Rfc822Name(email))
            },
            6 => {
                // uniformResourceIdentifier [6] IA5String
                let uri = core::str::from_utf8(name_data)
                    .map_err(|_| X509Error::InvalidExtension)?;
                Ok(GeneralName::UniformResourceIdentifier(uri))
            },
            _ => {
                // Other name types
                Ok(GeneralName::Other {
                    tag: tag_number as u8,
                    data: name_data,
                })
            }
        }
    }
}

impl<'a> AuthorityKeyIdentifier<'a> {
    /// Parse Authority Key Identifier extension
    fn parse(value: &'a [u8], critical: bool) -> X509Result<Self> {
        // AuthorityKeyIdentifier value is a DER-encoded SEQUENCE
        let (_, aki_seq) = DerParser::parse_value(value, 0)?;
        
        if !aki_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut key_identifier = None;
        let mut seq_iter = DerParser::parse_sequence(aki_seq.content, 1)?;
        
        // Parse optional keyIdentifier [0] KeyIdentifier
        if let Some(item_result) = seq_iter.next() {
            let item = item_result?;
            
            if item.tag.number == 0 {
                key_identifier = Some(item.content);
            }
        }
        
        // authorityCertIssuer and authorityCertSerialNumber not implemented
        
        Ok(AuthorityKeyIdentifier {
            key_identifier,
            authority_cert_issuer: None,
            authority_cert_serial: None,
            critical,
        })
    }
    
    /// Get key identifier
    pub fn key_identifier(&self) -> Option<&[u8]> {
        self.key_identifier
    }
    
    /// Check if extension is critical
    pub fn is_critical(&self) -> bool {
        self.critical
    }
}