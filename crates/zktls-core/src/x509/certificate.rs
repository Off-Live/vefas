//! X.509 certificate parsing implementation
//!
//! This module implements X.509 certificate parsing according to RFC 5280.
//! It extracts all fields needed for TLS 1.3 validation using the ASN.1 DER parser.

extern crate alloc;
use alloc::{vec::Vec, string::{String, ToString}};
use crate::asn1::{DerParser, DerValue, tag};
use super::{X509Error, X509Result, DistinguishedName, PublicKeyInfo, Validity, Extension, ExtensionType};

/// X.509 certificate representation
/// 
/// Based on RFC 5280 Certificate structure:
/// ```asn1
/// Certificate  ::=  SEQUENCE  {
///      tbsCertificate       TBSCertificate,
///      signatureAlgorithm   AlgorithmIdentifier,
///      signatureValue       BIT STRING  }
/// ```
#[derive(Debug, Clone)]
pub struct X509Certificate<'a> {
    /// Raw certificate DER data
    raw_data: &'a [u8],
    
    /// To-Be-Signed certificate DER data
    tbs_certificate_der: &'a [u8],
    
    /// To-Be-Signed certificate data
    tbs_certificate: TbsCertificate<'a>,
    
    /// Signature algorithm identifier
    signature_algorithm: String,
    
    /// Certificate signature value
    signature_value: &'a [u8],
}

/// To-Be-Signed Certificate structure
/// 
/// Based on RFC 5280 TBSCertificate structure:
/// ```asn1
/// TBSCertificate  ::=  SEQUENCE  {
///      version         [0]  EXPLICIT Version DEFAULT v1,
///      serialNumber         CertificateSerialNumber,
///      signature            AlgorithmIdentifier,
///      issuer               Name,
///      validity             Validity,
///      subject              Name,
///      subjectPublicKeyInfo SubjectPublicKeyInfo,
///      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///      extensions      [3]  EXPLICIT Extensions OPTIONAL }
/// ```
#[derive(Debug, Clone)]
pub struct TbsCertificate<'a> {
    /// Certificate version (1, 2, or 3)
    version: u8,
    
    /// Certificate serial number
    serial_number: &'a [u8],
    
    /// Signature algorithm identifier
    signature_algorithm: String,
    
    /// Certificate issuer
    issuer: DistinguishedName<'a>,
    
    /// Certificate validity period
    validity: Validity,
    
    /// Certificate subject
    subject: DistinguishedName<'a>,
    
    /// Subject public key information
    subject_public_key_info: PublicKeyInfo<'a>,
    
    /// Certificate extensions (v3 only)
    extensions: Vec<Extension<'a>>,
}

impl<'a> X509Certificate<'a> {
    /// Parse an X.509 certificate from DER-encoded bytes
    /// 
    /// # Arguments
    /// * `der_data` - DER-encoded certificate bytes
    /// 
    /// # Returns
    /// * `Ok(certificate)` - Parsed certificate
    /// * `Err(X509Error)` - Parsing error
    pub fn parse(der_data: &'a [u8]) -> X509Result<Self> {
        // Parse the outer SEQUENCE
        let (remaining, cert_seq) = DerParser::parse_value(der_data, 0)?;
        
        if !remaining.is_empty() {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        if !cert_seq.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        // Parse certificate components
        let mut seq_iter = DerParser::parse_sequence(cert_seq.content, 1)?;
        
        // Parse TBSCertificate
        let tbs_cert_value = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("tbsCertificate"))??;
        
        // Calculate the TBS certificate DER data position within the outer certificate
        // The TBS certificate is the first element in the certificate SEQUENCE
        let cert_content_start = cert_seq.content.as_ptr() as usize - der_data.as_ptr() as usize;
        let tbs_content_start = tbs_cert_value.content.as_ptr() as usize - der_data.as_ptr() as usize;
        let tbs_tag_length_size = tbs_content_start - cert_content_start;
        let tbs_start_in_cert = cert_content_start;
        let tbs_length = tbs_tag_length_size + tbs_cert_value.content.len();
        let tbs_certificate_der = &der_data[tbs_start_in_cert..tbs_start_in_cert + tbs_length];
        
        let tbs_certificate = Self::parse_tbs_certificate(&tbs_cert_value)?;
        
        // Parse signatureAlgorithm
        let sig_alg_value = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("signatureAlgorithm"))??;
        
        let signature_algorithm = Self::parse_algorithm_identifier(&sig_alg_value)?;
        
        // Parse signatureValue
        let sig_value = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("signatureValue"))??;
            
        if !sig_value.tag.matches(tag::BIT_STRING) {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        let (signature_data, _unused_bits) = DerParser::parse_bit_string(sig_value.content)?;
        
        // Ensure no extra data
        if seq_iter.next().is_some() {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        Ok(X509Certificate {
            raw_data: der_data,
            tbs_certificate_der,
            tbs_certificate,
            signature_algorithm,
            signature_value: signature_data,
        })
    }
    
    /// Parse TBSCertificate structure
    fn parse_tbs_certificate(tbs_value: &DerValue<'a>) -> X509Result<TbsCertificate<'a>> {
        if !tbs_value.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        let mut seq_iter = DerParser::parse_sequence(tbs_value.content, 2)?;
        
        // Parse version [0] EXPLICIT (optional, defaults to v1)
        let first_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("serialNumber"))??;
        
        let (version, serial_item) = if first_item.tag.number == 0 {
            // Version is present
            let version = Self::parse_version(&first_item)?;
            let serial_item = seq_iter.next()
                .ok_or(X509Error::MissingRequiredField("serialNumber"))??;
            (version, serial_item)
        } else {
            // Version defaults to v1 (0)
            (1, first_item)
        };
        
        // Parse serialNumber
        if !serial_item.tag.matches(tag::INTEGER) {
            return Err(X509Error::InvalidCertificateStructure);
        }
        let serial_number = DerParser::parse_integer(serial_item.content)?;
        
        // Parse signature algorithm
        let sig_alg_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("signature"))??;
        let signature_algorithm = Self::parse_algorithm_identifier(&sig_alg_item)?;
        
        // Parse issuer
        let issuer_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("issuer"))??;
        let issuer = DistinguishedName::parse(&issuer_item)?;
        
        // Parse validity
        let validity_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("validity"))??;
        let validity = Validity::parse(&validity_item)?;
        
        // Parse subject
        let subject_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("subject"))??;
        let subject = DistinguishedName::parse(&subject_item)?;
        
        // Parse subjectPublicKeyInfo
        let public_key_item = seq_iter.next()
            .ok_or(X509Error::MissingRequiredField("subjectPublicKeyInfo"))??;
        let subject_public_key_info = PublicKeyInfo::parse(&public_key_item)?;
        
        // Parse optional fields and extensions
        let mut extensions = Vec::new();
        
        // Skip issuerUniqueID [1] and subjectUniqueID [2] if present
        while let Some(next_item) = seq_iter.next() {
            let item = next_item?;
            match item.tag.number {
                1 => {
                    // issuerUniqueID [1] IMPLICIT - skip for now
                    continue;
                },
                2 => {
                    // subjectUniqueID [2] IMPLICIT - skip for now  
                    continue;
                },
                3 => {
                    // extensions [3] EXPLICIT
                    extensions = Self::parse_extensions(&item)?;
                    break;
                },
                _ => {
                    return Err(X509Error::InvalidCertificateStructure);
                }
            }
        }
        
        Ok(TbsCertificate {
            version,
            serial_number,
            signature_algorithm,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            extensions,
        })
    }
    
    /// Parse certificate version from [0] EXPLICIT context tag
    fn parse_version(version_item: &DerValue) -> X509Result<u8> {
        // Version is [0] EXPLICIT Version
        let version_content = DerParser::parse_value(version_item.content, 3)?;
        
        if !version_content.1.tag.matches(tag::INTEGER) {
            return Err(X509Error::InvalidCertificateStructure);
        }
        
        let version_bytes = DerParser::parse_integer(version_content.1.content)?;
        
        if version_bytes.is_empty() || version_bytes.len() > 1 {
            return Err(X509Error::UnsupportedVersion(0));
        }
        
        let version_value = version_bytes[0];
        
        // Convert ASN.1 version (0, 1, 2) to X.509 version (1, 2, 3)
        let version = version_value + 1;
        
        if !(1..=3).contains(&version) {
            return Err(X509Error::UnsupportedVersion(version));
        }
        
        Ok(version)
    }
    
    /// Parse AlgorithmIdentifier structure
    fn parse_algorithm_identifier(alg_item: &DerValue) -> X509Result<String> {
        if !alg_item.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidSignatureAlgorithm);
        }
        
        let mut seq_iter = DerParser::parse_sequence(alg_item.content, 2)?;
        
        // Parse algorithm OID
        let oid_item = seq_iter.next()
            .ok_or(X509Error::InvalidSignatureAlgorithm)??;
            
        if !oid_item.tag.matches(tag::OBJECT_IDENTIFIER) {
            return Err(X509Error::InvalidSignatureAlgorithm);
        }
        
        let oid_components = DerParser::parse_oid(oid_item.content)?;
        let oid_string = oid_components.iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(".");
        
        // Map common OIDs to algorithm names
        let algorithm = match oid_string.as_str() {
            "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
            "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
            "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
            "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
            _ => &oid_string, // Use OID if unknown
        };
        
        Ok(String::from(algorithm))
    }
    
    /// Parse certificate extensions
    fn parse_extensions(ext_item: &DerValue<'a>) -> X509Result<Vec<Extension<'a>>> {
        // Extensions are [3] EXPLICIT Extensions
        let ext_seq = DerParser::parse_value(ext_item.content, 3)?;
        
        if !ext_seq.1.tag.matches(tag::SEQUENCE) {
            return Err(X509Error::InvalidExtension);
        }
        
        let mut extensions = Vec::new();
        let mut seq_iter = DerParser::parse_sequence(ext_seq.1.content, 4)?;
        
        while let Some(ext_result) = seq_iter.next() {
            let ext_value = ext_result?;
            let extension = Extension::parse(&ext_value)?;
            extensions.push(extension);
        }
        
        Ok(extensions)
    }
    
    // Accessor methods for the parsed certificate data
    
    /// Get certificate version (1, 2, or 3)
    pub fn version(&self) -> u8 {
        self.tbs_certificate.version
    }
    
    /// Get certificate serial number
    pub fn serial_number(&self) -> &[u8] {
        self.tbs_certificate.serial_number
    }
    
    /// Get signature algorithm
    pub fn signature_algorithm(&self) -> &str {
        &self.signature_algorithm
    }
    
    /// Get certificate issuer
    pub fn issuer(&self) -> &DistinguishedName {
        &self.tbs_certificate.issuer
    }
    
    /// Get certificate subject
    pub fn subject(&self) -> &DistinguishedName {
        &self.tbs_certificate.subject
    }
    
    /// Get certificate validity period
    pub fn validity(&self) -> &Validity {
        &self.tbs_certificate.validity
    }
    
    /// Get subject public key information
    pub fn public_key(&self) -> &PublicKeyInfo {
        &self.tbs_certificate.subject_public_key_info
    }
    
    /// Get certificate extensions
    pub fn extensions(&self) -> &[Extension] {
        &self.tbs_certificate.extensions
    }
    
    /// Get basic constraints extension
    pub fn basic_constraints(&self) -> Option<&Extension> {
        self.extensions().iter()
            .find(|ext| matches!(ext.extension_type(), ExtensionType::BasicConstraints(_)))
    }
    
    /// Get raw certificate data
    pub fn raw_data(&self) -> &[u8] {
        self.raw_data
    }
    
    /// Get the TBS (To-Be-Signed) certificate data
    /// 
    /// This is the portion of the certificate that is actually signed,
    /// needed for signature verification.
    pub fn tbs_certificate_data(&self) -> &[u8] {
        self.tbs_certificate_der
    }
    
    /// Get the certificate signature bytes
    /// 
    /// This is the signature value from the certificate, needed for verification.
    pub fn signature_bytes(&self) -> &[u8] {
        self.signature_value
    }
}