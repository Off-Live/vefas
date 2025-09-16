//! Public key information parsing for X.509 certificates
//!
//! This module implements SubjectPublicKeyInfo parsing according to RFC 5280.
//! Supports RSA, ECDSA P-256, and Ed25519 public keys for TLS 1.3.

extern crate alloc;
use alloc::{string::{String, ToString}, vec::Vec, format};
use crate::asn1::{DerParser, DerValue, tag};
use super::{X509Error, X509Result};

/// Subject Public Key Information
/// 
/// Based on RFC 5280 SubjectPublicKeyInfo structure:
/// ```asn1
/// SubjectPublicKeyInfo  ::=  SEQUENCE  {
///      algorithm            AlgorithmIdentifier,
///      subjectPublicKey     BIT STRING  }
/// ```
#[derive(Debug, Clone)]
pub struct PublicKeyInfo<'a> {
    /// Public key algorithm identifier
    algorithm: String,
    
    /// Algorithm parameters (for ECDSA curves)
    parameters: Option<String>,
    
    /// Public key data
    key_data: &'a [u8],
    
    /// Raw SubjectPublicKeyInfo for verification
    raw_data: &'a [u8],
}

impl<'a> PublicKeyInfo<'a> {
    /// Parse SubjectPublicKeyInfo from ASN.1 DER
    pub fn parse(spki_value: &DerValue<'a>) -> X509Result<Self> {
        if !spki_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let mut seq_iter = DerParser::parse_sequence(spki_value.content, 1)?;
        
        // Parse algorithm identifier
        let alg_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("algorithm"))??;
            
        let (algorithm, parameters) = Self::parse_algorithm_identifier(&alg_item)?;
        
        // Parse subjectPublicKey (BIT STRING)
        let key_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("subjectPublicKey"))??;
            
        if !key_item.tag.matches(tag::BIT_STRING) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let (key_data, unused_bits) = DerParser::parse_bit_string(key_item.content)?;
        
        if unused_bits != 0 {
            return Err(X509Error::InvalidPublicKey);
        }
        
        Ok(PublicKeyInfo {
            algorithm,
            parameters,
            key_data,
            raw_data: spki_value.content,
        })
    }
    
    /// Parse AlgorithmIdentifier for public key algorithms
    fn parse_algorithm_identifier(alg_item: &DerValue) -> X509Result<(String, Option<String>)> {
        if !alg_item.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let mut seq_iter = DerParser::parse_sequence(alg_item.content, 1)?;
        
        // Parse algorithm OID
        let oid_item = seq_iter.next()
            .ok_or(X509Error::InvalidPublicKey)??;
            
        if !oid_item.tag.matches(tag::OBJECT_IDENTIFIER) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let oid_components = DerParser::parse_oid(oid_item.content)?;
        let oid_string = oid_components.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(".");
        
        // Map OID to algorithm name
        let algorithm = match oid_string.as_str() {
            "1.2.840.113549.1.1.1" => "rsaEncryption",
            "1.2.840.10045.2.1" => "id-ecPublicKey",
            "1.3.101.112" => "id-Ed25519",
            _ => {
                return Err(X509Error::UnsupportedPublicKeyAlgorithm(oid_string));
            }
        };
        
        // Parse optional parameters
        let parameters = if let Some(param_result) = seq_iter.next() {
            let param_item = param_result?;
            
            match algorithm {
                "id-ecPublicKey" => {
                    // For ECDSA, parameters contain the curve OID
                    if !param_item.tag.matches(tag::OBJECT_IDENTIFIER) {
                        return Err(X509Error::InvalidPublicKey);
                    }
                    
                    let curve_oid_components = DerParser::parse_oid(param_item.content)?;
                    let curve_oid = curve_oid_components.iter()
                        .map(|x| x.to_string())
                        .collect::<Vec<_>>()
                        .join(".");
                    
                    Some(curve_oid)
                },
                "rsaEncryption" => {
                    // RSA parameters should be NULL
                    if !param_item.tag.matches(tag::NULL) {
                        return Err(X509Error::InvalidPublicKey);
                    }
                    None
                },
                _ => None,
            }
        } else {
            None
        };
        
        Ok((String::from(algorithm), parameters))
    }
    
    /// Get public key algorithm name
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    
    /// Get curve OID for ECDSA keys
    pub fn curve_oid(&self) -> Option<&str> {
        self.parameters.as_deref()
    }
    
    /// Get public key data
    pub fn key_data(&self) -> &[u8] {
        self.key_data
    }
    
    /// Get raw SubjectPublicKeyInfo data
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
    
    /// Validate ECDSA public key point is on the specified curve
    pub fn validate_curve_point(&self) -> X509Result<()> {
        if self.algorithm != "id-ecPublicKey" {
            return Err(X509Error::InvalidPublicKey);
        }
        
        match self.curve_oid() {
            Some("1.2.840.10045.3.1.7") => {
                // prime256v1 (P-256)
                self.validate_p256_point()
            },
            Some(curve) => {
                Err(X509Error::UnsupportedPublicKeyAlgorithm(
                    format!("Unsupported curve: {}", curve)
                ))
            },
            None => Err(X509Error::InvalidPublicKey),
        }
    }
    
    /// Validate P-256 public key point
    fn validate_p256_point(&self) -> X509Result<()> {
        // P-256 public key should be 65 bytes: 0x04 + 32-byte X + 32-byte Y
        if self.key_data.len() != 65 {
            return Err(X509Error::InvalidPublicKey);
        }
        
        // First byte should be 0x04 (uncompressed point format)
        if self.key_data[0] != 0x04 {
            return Err(X509Error::InvalidPublicKey);
        }
        
        // For now, we just validate the format. In a full implementation,
        // we would verify the point is on the P-256 curve using the equation:
        // y² ≡ x³ - 3x + b (mod p) where p is the P-256 prime
        
        Ok(())
    }
    
    /// Validate RSA public key parameters
    pub fn validate_rsa_params(&self) -> X509Result<()> {
        if self.algorithm != "rsaEncryption" {
            return Err(X509Error::InvalidPublicKey);
        }
        
        // RSA public key is encoded as:
        // RSAPublicKey ::= SEQUENCE {
        //     modulus           INTEGER,  -- n
        //     publicExponent    INTEGER   -- e
        // }
        
        let (_, rsa_key_seq) = DerParser::parse_value(self.key_data, 0)?;
        
        if !rsa_key_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let mut seq_iter = DerParser::parse_sequence(rsa_key_seq.content, 1)?;
        
        // Parse modulus
        let modulus_item = seq_iter.next()
            .ok_or(X509Error::InvalidPublicKey)??;
            
        if !modulus_item.tag.matches(tag::INTEGER) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let modulus = DerParser::parse_integer(modulus_item.content)?;
        
        // Parse public exponent
        let exponent_item = seq_iter.next()
            .ok_or(X509Error::InvalidPublicKey)??;
            
        if !exponent_item.tag.matches(tag::INTEGER) {
            return Err(X509Error::InvalidPublicKey);
        }
        
        let exponent = DerParser::parse_integer(exponent_item.content)?;
        
        // Basic validation
        if modulus.is_empty() || exponent.is_empty() {
            return Err(X509Error::InvalidPublicKey);
        }
        
        // Common exponent values are 3 or 65537 (0x010001)
        let exp_valid = exponent == &[0x03] || 
                       exponent == &[0x01, 0x00, 0x01] ||
                       (exponent.len() <= 4 && !exponent.is_empty());
        
        if !exp_valid {
            return Err(X509Error::InvalidPublicKey);
        }
        
        Ok(())
    }
    
    /// Extract ECDSA P-256 public key in uncompressed format (64 bytes)
    /// 
    /// For signature verification, we need the raw X and Y coordinates without the 0x04 prefix
    pub fn extract_ecdsa_public_key(&self) -> X509Result<Vec<u8>> {
        if self.algorithm != "id-ecPublicKey" {
            return Err(X509Error::UnsupportedPublicKeyAlgorithm(
                "Not an ECDSA public key".to_string()
            ));
        }
        
        // Verify this is P-256
        match self.curve_oid() {
            Some("1.2.840.10045.3.1.7") => {}, // prime256v1 (P-256)
            Some(curve) => {
                return Err(X509Error::UnsupportedPublicKeyAlgorithm(
                    format!("Unsupported curve: {}", curve)
                ));
            },
            None => return Err(X509Error::InvalidPublicKey),
        }
        
        // Validate format
        self.validate_p256_point()?;
        
        // Extract X and Y coordinates (skip the 0x04 prefix)
        Ok(self.key_data[1..].to_vec()) // 64 bytes: 32-byte X + 32-byte Y
    }
    
    /// Extract RSA public key in DER format for signature verification
    pub fn extract_rsa_public_key(&self) -> X509Result<Vec<u8>> {
        if self.algorithm != "rsaEncryption" {
            return Err(X509Error::UnsupportedPublicKeyAlgorithm(
                "Not an RSA public key".to_string()
            ));
        }
        
        // Validate RSA parameters
        self.validate_rsa_params()?;
        
        // Return the raw key data (RSAPublicKey DER)
        Ok(self.key_data.to_vec())
    }
    
    /// Extract Ed25519 public key (32 bytes)
    pub fn extract_ed25519_public_key(&self) -> X509Result<Vec<u8>> {
        if self.algorithm != "id-Ed25519" {
            return Err(X509Error::UnsupportedPublicKeyAlgorithm(
                "Not an Ed25519 public key".to_string()
            ));
        }
        
        // Ed25519 public key should be exactly 32 bytes
        if self.key_data.len() != 32 {
            return Err(X509Error::InvalidPublicKey);
        }
        
        Ok(self.key_data.to_vec())
    }
}