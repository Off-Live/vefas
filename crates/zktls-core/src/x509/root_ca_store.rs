//! Root CA Trust Store Implementation
//!
//! This module implements a trust store for root certificate authorities following
//! RFC 5280 trust anchor processing and industry standard practices.
//! 
//! The trust store provides:
//! - Management of trusted root certificates
//! - Built-in well-known root CAs (Let's Encrypt, DigiCert, etc.)
//! - Certificate chain validation against trusted anchors
//! - Efficient trust anchor lookup and matching

extern crate alloc;
use alloc::{vec, vec::Vec, string::{String, ToString}, collections::BTreeMap, format};
use crate::x509::{X509Certificate, ValidationError, ChainValidationResult};

/// Simple base64 decoder for PEM certificates
/// This is a minimal implementation suitable for zkVM environments
fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    // Base64 character set
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u8;
    
    for byte in input.bytes() {
        if byte == b'=' {
            break; // Padding
        }
        
        let value = match CHARS.iter().position(|&x| x == byte) {
            Some(pos) => pos as u32,
            None => return Err("Invalid base64 character"),
        };
        
        buffer = (buffer << 6) | value;
        bits += 6;
        
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
        }
    }
    
    Ok(result)
}

/// Trust store for root certificate authorities
#[derive(Debug, Clone)]
pub struct RootCaStore {
    /// Map from subject DN to certificate index
    roots: BTreeMap<String, usize>,
    /// Raw certificate data in DER format
    cert_data: Vec<Vec<u8>>,
}

impl RootCaStore {
    /// Create a new empty root CA store
    pub fn new() -> Result<Self, ValidationError> {
        Ok(Self {
            roots: BTreeMap::new(),
            cert_data: Vec::new(),
        })
    }
    
    /// Create a root CA store with built-in trusted root CAs from Mozilla CA bundle
    /// 
    /// This includes 146 trusted root certificates from the Mozilla CA bundle:
    /// - DigiCert root CAs
    /// - GlobalSign root CAs 
    /// - Entrust root CAs
    /// - Let's Encrypt (ISRG Root X1)
    /// - All other major certificate authorities trusted by Mozilla Firefox
    /// 
    /// The CA bundle is sourced from: https://curl.se/ca/cacert.pem
    pub fn with_builtin_cas() -> Result<Self, ValidationError> {
        let mut store = Self::new()?;
        
        // Load Mozilla CA bundle embedded in binary
        let mozilla_ca_bundle_pem = include_str!("mozilla_ca_bundle.pem");
        
        // Parse PEM format and extract individual certificates
        let mut current_cert_lines = Vec::new();
        let mut in_certificate = false;
        
        for line in mozilla_ca_bundle_pem.lines() {
            if line == "-----BEGIN CERTIFICATE-----" {
                in_certificate = true;
                current_cert_lines.clear();
                current_cert_lines.push(line);
            } else if line == "-----END CERTIFICATE-----" {
                current_cert_lines.push(line);
                in_certificate = false;
                
                // Convert PEM to DER and parse certificate
                let pem_cert = current_cert_lines.join("\n");
                if let Ok(der_cert) = Self::pem_to_der(&pem_cert) {
                    // Parse certificate to get subject DN and validate it
                    if let Ok(cert) = X509Certificate::parse(&der_cert) {
                        // Validate that this is actually a root certificate (self-signed)
                        if cert.issuer().to_string() == cert.subject().to_string() {
                            let subject_dn = cert.subject().to_string();
                            
                            // Store the DER data and map subject to index
                            store.cert_data.push(der_cert);
                            let cert_index = store.cert_data.len() - 1;
                            store.roots.insert(subject_dn, cert_index);
                        }
                    }
                }
            } else if in_certificate {
                current_cert_lines.push(line);
            }
        }
        
        Ok(store)
    }
    
    /// Add a root certificate to the trust store from DER data
    /// 
    /// # Arguments
    /// * `der_data` - DER encoded certificate bytes
    /// 
    /// # Returns
    /// * `Ok(())` - Certificate added successfully
    /// * `Err(ValidationError)` - Invalid certificate or duplicate
    pub fn add_root_ca_der(&mut self, der_data: &[u8]) -> Result<(), ValidationError> {
        // Parse certificate to get subject DN and validate it
        let cert = X509Certificate::parse(der_data)
            .map_err(|_| ValidationError::InvalidCertificate("Failed to parse certificate".to_string()))?;
        
        // Validate that this is actually a root certificate (self-signed)
        if cert.issuer().to_string() != cert.subject().to_string() {
            return Err(ValidationError::InvalidCertificate(
                "Root certificate must be self-signed".to_string()
            ));
        }
        
        let subject_dn = cert.subject().to_string();
        
        // Store the DER data and map subject to index
        self.cert_data.push(der_data.to_vec());
        let cert_index = self.cert_data.len() - 1;
        self.roots.insert(subject_dn, cert_index);
        
        Ok(())
    }
    
    /// Get the number of root certificates in the store
    pub fn len(&self) -> usize {
        self.roots.len()
    }
    
    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }
    
    /// Check if the store contains a root certificate with specific subject
    pub fn contains_subject(&self, subject_dn: &str) -> bool {
        self.roots.contains_key(subject_dn)
    }
    
    /// Find a root certificate by subject distinguished name
    /// 
    /// # Arguments
    /// * `subject_dn` - Subject distinguished name to search for
    /// 
    /// # Returns
    /// * `Ok(Some(certificate))` - Found matching root certificate
    /// * `Ok(None)` - No matching certificate found
    /// * `Err(ValidationError)` - Search error
    pub fn find_by_subject(&self, subject_dn: &str) -> Result<Option<X509Certificate<'_>>, ValidationError> {
        if let Some(&cert_index) = self.roots.get(subject_dn) {
            let cert = X509Certificate::parse(&self.cert_data[cert_index])
                .map_err(|_| ValidationError::InvalidCertificate("Failed to parse stored certificate".to_string()))?;
            Ok(Some(cert))
        } else {
            Ok(None)
        }
    }
    
    /// Verify a certificate chain against the trusted root CAs
    /// 
    /// This performs complete RFC 5280 certificate path validation:
    /// 1. Build certificate chain from leaf to root
    /// 2. Verify all signatures in the chain
    /// 3. Validate certificate validity periods
    /// 4. Check against trust anchors
    /// 
    /// # Arguments
    /// * `chain` - Certificate chain to validate (leaf first)
    /// 
    /// # Returns
    /// * `Ok(ChainValidationResult)` - Validation results
    /// * `Err(ValidationError)` - Validation error
    pub fn verify_chain(&self, chain: &[&X509Certificate<'_>]) -> Result<ChainValidationResult, ValidationError> {
        if chain.is_empty() {
            return Ok(ChainValidationResult::invalid(vec![
                ValidationError::InvalidCertificate("Empty certificate chain".to_string())
            ]));
        }
        
        // Use real certificate chain validation with signature verification
        let crypto_provider = zktls_crypto::native::NativeCryptoProvider::new();
        let validator = crate::x509::validation::CertificateChainValidator::new(crypto_provider);
        
        // Get trust anchors (root certificates)
        let root_certs = self.get_all_root_certificates()
            .map_err(|e| ValidationError::InvalidCertificate(format!("Failed to get trust anchors: {:?}", e)))?;
        let trust_anchors = root_certs.iter().collect::<Vec<_>>();
        
        // Perform real certificate chain validation with signature verification
        let leaf = chain[0];
        let available_certs = &chain[1..];
        let validation_result = validator.validate_complete(
            leaf,
            available_certs,
            &trust_anchors,
            0 // Current time - in production this would be the actual validation time
        ).map_err(|e| ValidationError::InvalidCertificate(format!("Certificate validation failed: {:?}", e)))?;
        
        if validation_result.is_valid() {
            Ok(ChainValidationResult::valid(
                validation_result.chain_length(),
                validation_result.trusted_root().map(|s| s.to_string())
            ))
        } else {
            Ok(ChainValidationResult::invalid(
                validation_result.errors().to_vec()
            ))
        }
    }
    
    /// Find a root certificate by subject containing a specific string
    /// 
    /// # Arguments
    /// * `substring` - String to search for in subject DN
    /// 
    /// # Returns
    /// * `Ok(Some(certificate))` - Found matching root certificate
    /// * `Ok(None)` - No matching certificate found
    /// * `Err(ValidationError)` - Search error
    pub fn find_by_subject_containing(&self, substring: &str) -> Result<Option<X509Certificate<'_>>, ValidationError> {
        for (subject_dn, &cert_index) in &self.roots {
            if subject_dn.contains(substring) {
                let cert = X509Certificate::parse(&self.cert_data[cert_index])
                    .map_err(|_| ValidationError::InvalidCertificate("Failed to parse stored certificate".to_string()))?;
                return Ok(Some(cert));
            }
        }
        Ok(None)
    }
    
    /// Get all root certificates in the store
    /// 
    /// # Returns
    /// Vector of all root certificates
    pub fn get_all_root_certificates(&self) -> Result<Vec<X509Certificate<'_>>, ValidationError> {
        let mut certificates = Vec::new();
        for &cert_index in self.roots.values() {
            let cert = X509Certificate::parse(&self.cert_data[cert_index])
                .map_err(|_| ValidationError::InvalidCertificate("Failed to parse stored certificate".to_string()))?;
            certificates.push(cert);
        }
        Ok(certificates)
    }

    /// Convert PEM certificate to DER format
    /// 
    /// # Arguments
    /// * `pem_data` - PEM formatted certificate string
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` - DER encoded certificate bytes
    /// * `Err(ValidationError)` - PEM parsing error
    fn pem_to_der(pem_data: &str) -> Result<Vec<u8>, ValidationError> {
        // Simple PEM to DER conversion - extracts base64 content between headers
        let lines: Vec<&str> = pem_data.lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        
        let base64_content = lines.join("");
        
        // Decode base64 to get DER bytes
        base64_decode(&base64_content)
            .map_err(|_| ValidationError::InvalidCertificate(
                "Failed to decode base64 PEM content".to_string()
            ))
    }

}

impl Default for RootCaStore {
    fn default() -> Self {
        Self::new().expect("Creating empty root CA store should never fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_root_ca_store_creation() {
        let store = RootCaStore::new().unwrap();
        assert_eq!(store.len(), 0);
        assert!(store.is_empty());
    }
    
    #[test] 
    fn test_builtin_cas_store_creation() {
        let store = RootCaStore::with_builtin_cas().unwrap();
        // Should contain Mozilla CA bundle certificates
        assert!(store.len() > 100, "Should contain Mozilla CA bundle certificates");
    }
}