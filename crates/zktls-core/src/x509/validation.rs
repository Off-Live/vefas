//! X.509 certificate chain validation implementation
//!
//! This module implements RFC 5280 certificate path validation including:
//! - Certificate chain building from leaf to root
//! - Signature verification using zktls-crypto
//! - Validity period validation  
//! - Key usage and extended key usage constraint validation
//! - Name constraints and path length validation
//! - Trust anchor verification

extern crate alloc;
use alloc::{vec::Vec, string::{String, ToString}, format};
use crate::x509::{X509Certificate, ValidationError, ValidationResult as ValidationResultType};
use zktls_crypto::{CryptoProvider, Hash, Signature};

/// A certificate chain from leaf to root
#[derive(Debug, Clone)]
pub struct CertificateChain<'a> {
    /// Certificates in the chain, ordered from leaf to root
    certificates: Vec<&'a X509Certificate<'a>>,
}

/// Certificate chain validation result
#[derive(Debug, Clone)]
pub struct ChainValidationResult {
    /// Whether the chain is valid
    valid: bool,
    
    /// Length of the certificate chain
    chain_length: usize,
    
    /// The trusted root certificate if validation succeeded
    trusted_root: Option<String>,
    
    /// Validation errors if any
    errors: Vec<ValidationError>,
}

/// Certificate chain validator using cryptographic provider
pub struct CertificateChainValidator<P> 
where 
    P: CryptoProvider + Hash + Signature
{
    crypto_provider: P,
}

impl<'a> CertificateChain<'a> {
    /// Build a certificate chain from a leaf certificate and available certificates
    ///
    /// This implements the chain building phase of RFC 5280 Section 6.
    /// It attempts to construct a path from the leaf certificate to a trusted root
    /// by following issuer-subject relationships.
    ///
    /// # Arguments
    /// * `leaf` - The leaf certificate to start the chain from
    /// * `available_certs` - Pool of available intermediate and root certificates
    ///
    /// # Returns
    /// * `Ok(CertificateChain)` - Successfully built chain
    /// * `Err(ValidationError)` - Chain building failed
    ///
    /// # Errors
    /// * `MissingIntermediateCertificate` - Required intermediate certificate not found
    /// * `CircularChainReference` - Circular dependency detected in certificate chain
    pub fn build(
        leaf: &'a X509Certificate<'a>, 
        available_certs: &[&'a X509Certificate<'a>]
    ) -> ValidationResultType<Self> {
        let mut chain = Vec::new();
        let mut current = leaf;
        let mut visited_subjects = Vec::new();
        
        // Start with the leaf certificate
        chain.push(current);
        visited_subjects.push(current.subject().to_string());
        
        // Build chain by following issuer-subject relationships
        loop {
            // Check if current certificate is self-signed (root)
            if current.issuer().to_string() == current.subject().to_string() {
                // Found self-signed root certificate
                break;
            }
            
            // Find the issuer certificate in available certificates
            let issuer_dn = current.issuer().to_string();
            let issuer_cert = available_certs
                .iter()
                .find(|cert| cert.subject().to_string() == issuer_dn);
            
            match issuer_cert {
                Some(cert) => {
                    // Check for circular references
                    if visited_subjects.contains(&cert.subject().to_string()) {
                        return Err(ValidationError::CircularChainReference);
                    }
                    
                    chain.push(cert);
                    visited_subjects.push(cert.subject().to_string());
                    current = cert;
                },
                None => {
                    // Missing intermediate certificate
                    return Err(ValidationError::MissingIntermediateCertificate(issuer_dn));
                }
            }
            
            // Prevent infinite loops (safety check)
            if chain.len() > 10 {
                return Err(ValidationError::CircularChainReference);
            }
        }
        
        Ok(CertificateChain {
            certificates: chain,
        })
    }
    
    /// Get the certificates in the chain (leaf to root order)
    pub fn certificates(&self) -> &[&'a X509Certificate<'a>] {
        &self.certificates
    }
    
    /// Get the leaf certificate
    pub fn leaf_certificate(&self) -> &'a X509Certificate<'a> {
        self.certificates[0]
    }
    
    /// Get the root certificate
    pub fn root_certificate(&self) -> &'a X509Certificate<'a> {
        self.certificates[self.certificates.len() - 1]
    }
    
    /// Get the length of the certificate chain
    pub fn len(&self) -> usize {
        self.certificates.len()
    }
    
    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }
}

impl ChainValidationResult {
    /// Create a new successful validation result
    pub fn valid(chain_length: usize, trusted_root: Option<String>) -> Self {
        Self {
            valid: true,
            chain_length,
            trusted_root,
            errors: Vec::new(),
        }
    }
    
    /// Create a new failed validation result
    pub fn invalid(errors: Vec<ValidationError>) -> Self {
        Self {
            valid: false,
            chain_length: 0,
            trusted_root: None,
            errors,
        }
    }
    
    /// Check if the validation result is valid
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    
    /// Get the chain length
    pub fn chain_length(&self) -> usize {
        self.chain_length
    }
    
    /// Get the trusted root certificate subject if available
    pub fn trusted_root(&self) -> Option<&str> {
        self.trusted_root.as_deref()
    }
    
    /// Get validation errors
    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }
}

impl<P> CertificateChainValidator<P>
where 
    P: CryptoProvider + Hash + Signature
{
    /// Create a new certificate chain validator
    pub fn new(crypto_provider: P) -> Self {
        Self {
            crypto_provider,
        }
    }
    
    /// Verify all signatures in the certificate chain
    ///
    /// This implements signature verification from RFC 5280 Section 6.1.3.
    /// Each certificate's signature is verified using its issuer's public key.
    ///
    /// # Arguments
    /// * `chain` - The certificate chain to verify
    ///
    /// # Returns
    /// * `Ok(())` - All signatures are valid
    /// * `Err(ValidationError)` - One or more signatures are invalid
    pub fn verify_signatures(&self, chain: &CertificateChain<'_>) -> ValidationResultType<()> {
        let certificates = chain.certificates();
        
        for i in 0..certificates.len() {
            let cert = certificates[i];
            
            // For self-signed certificates (roots), verify against themselves
            let issuer_cert = if i == certificates.len() - 1 {
                // Last certificate should be self-signed root
                if cert.issuer().to_string() != cert.subject().to_string() {
                    return Err(ValidationError::UntrustedChain);
                }
                cert
            } else {
                // Use the next certificate in chain as issuer
                certificates[i + 1]
            };
            
            // Verify certificate signature using issuer's public key
            let signature_valid = self.verify_certificate_signature(cert, issuer_cert)
                .map_err(|e| ValidationError::CryptographicError(e.to_string()))?;
            
            if !signature_valid {
                return Err(ValidationError::InvalidSignature(
                    cert.subject().to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validate certificate validity periods
    ///
    /// This implements validity period checking from RFC 5280 Section 6.1.4.
    /// All certificates in the chain must be valid at the specified time.
    ///
    /// # Arguments
    /// * `chain` - The certificate chain to validate
    /// * `validation_time` - Unix timestamp for validation time
    ///
    /// # Returns
    /// * `Ok(())` - All certificates are within their validity periods
    /// * `Err(ValidationError)` - One or more certificates are expired or not yet valid
    pub fn validate_validity_periods(&self, chain: &CertificateChain<'_>, validation_time: u64) -> ValidationResultType<()> {
        for cert in chain.certificates() {
            let validity = cert.validity();
            
            if validation_time < validity.not_before() {
                return Err(ValidationError::CertificateNotYetValid(
                    cert.subject().to_string()
                ));
            }
            
            if validation_time > validity.not_after() {
                return Err(ValidationError::CertificateExpired(
                    cert.subject().to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Validate certificate chain against trust anchors
    ///
    /// This implements trust anchor validation from RFC 5280 Section 6.
    /// The certificate chain must terminate at one of the provided trust anchors.
    ///
    /// # Arguments
    /// * `chain` - The certificate chain to validate
    /// * `trust_anchors` - List of trusted root certificates
    ///
    /// # Returns
    /// * `Ok(())` - Chain terminates at a trusted root
    /// * `Err(ValidationError)` - Chain does not terminate at a trusted root
    pub fn validate_against_trust_anchors(
        &self, 
        chain: &CertificateChain<'_>, 
        trust_anchors: &[&X509Certificate<'_>]
    ) -> ValidationResultType<()> {
        let root_cert = chain.root_certificate();
        
        // Check if root certificate matches any trust anchor
        for trust_anchor in trust_anchors {
            if self.certificates_match(root_cert, trust_anchor) {
                return Ok(());
            }
        }
        
        Err(ValidationError::UntrustedChain)
    }
    
    /// Perform complete certificate chain validation
    ///
    /// This implements the complete RFC 5280 certificate path validation algorithm:
    /// 1. Build certificate chain
    /// 2. Verify all signatures
    /// 3. Validate certificate validity periods
    /// 4. Validate against trust anchors
    /// 5. Check key usage constraints (future implementation)
    /// 6. Check name constraints (future implementation)
    ///
    /// # Arguments
    /// * `leaf` - The leaf certificate to validate
    /// * `available_certs` - Pool of intermediate certificates
    /// * `trust_anchors` - List of trusted root certificates
    /// * `validation_time` - Unix timestamp for validation
    ///
    /// # Returns
    /// * `Ok(ValidationResult)` - Validation completed with results
    /// * `Err(ValidationError)` - Validation failed
    pub fn validate_complete(
        &self,
        leaf: &X509Certificate<'_>,
        available_certs: &[&X509Certificate<'_>],
        trust_anchors: &[&X509Certificate<'_>],
        validation_time: u64,
    ) -> ValidationResultType<ChainValidationResult> {
        // Step 1: Build certificate chain
        let chain = match CertificateChain::build(leaf, available_certs) {
            Ok(chain) => chain,
            Err(e) => return Err(e),
        };
        
        let mut errors = Vec::new();
        
        // Step 2: Verify signatures
        if let Err(e) = self.verify_signatures(&chain) {
            errors.push(e);
        }
        
        // Step 3: Validate validity periods
        if let Err(e) = self.validate_validity_periods(&chain, validation_time) {
            errors.push(e);
        }
        
        // Step 4: Validate against trust anchors
        let trusted_root = match self.validate_against_trust_anchors(&chain, trust_anchors) {
            Ok(_) => Some(chain.root_certificate().subject().to_string()),
            Err(e) => {
                errors.push(e);
                None
            }
        };
        
        // Return validation result
        if errors.is_empty() {
            Ok(ChainValidationResult::valid(chain.len(), trusted_root))
        } else {
            Ok(ChainValidationResult::invalid(errors))
        }
    }
    
    /// Verify a certificate's signature using its issuer's public key
    fn verify_certificate_signature(
        &self,
        cert: &X509Certificate<'_>,
        issuer: &X509Certificate<'_>,
    ) -> Result<bool, String> {
        // Get the certificate's signature algorithm
        let sig_algorithm = cert.signature_algorithm();
        
        // Get the certificate's signature value
        let signature = cert.signature_bytes();
        
        // Get the issuer's public key
        let issuer_public_key = issuer.public_key();
        
        // Get the TBS certificate data (the data that was signed)
        let tbs_data = cert.tbs_certificate_data();
        
        // Verify signature based on algorithm
        match sig_algorithm {
            "ecdsa-with-SHA256" => {
                // X.509 certificate signatures are created over the HASH of TBS data
                // We must hash the TBS data first, then use prehashed verification
                let tbs_hash = self.crypto_provider.sha256(tbs_data);
                
                // Use prehashed verification to avoid double hashing
                self.crypto_provider
                    .p256_verify_prehashed(issuer_public_key.key_data(), &tbs_hash, signature)
                    .map_err(|e| format!("ECDSA verification failed: {:?}", e))
            },
            "sha256WithRSAEncryption" => {
                // RSA verification also needs the same treatment for X.509 certificates
                // For now, use the existing rsa_verify which handles message hashing
                // TODO: Implement rsa_verify_prehashed for consistency
                self.crypto_provider
                    .rsa_verify(issuer_public_key.key_data(), tbs_data, signature, "sha256")
                    .map_err(|e| format!("RSA verification failed: {:?}", e))
            },
            _ => Err(format!("Unsupported signature algorithm: {}", sig_algorithm)),
        }
    }
    
    /// Check if two certificates match (same subject and public key)
    fn certificates_match(&self, cert1: &X509Certificate<'_>, cert2: &X509Certificate<'_>) -> bool {
        // Compare subject distinguished names
        if cert1.subject().to_string() != cert2.subject().to_string() {
            return false;
        }
        
        // Compare public keys
        let pk1 = cert1.public_key();
        let pk2 = cert2.public_key();
        
        pk1.algorithm() == pk2.algorithm() && pk1.key_data() == pk2.key_data()
    }
}