//! Certificate validation utilities for VEFAS
//!
//! This module provides comprehensive X.509 certificate validation capabilities
//! that can be shared across different zkVM platforms. The validation logic
//! includes DER parsing, certificate chain verification, and domain matching
//! suitable for zero-knowledge proof contexts.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

// Debug macro that works in both std and no_std environments
macro_rules! debug_print {
    ($($arg:tt)*) => {
        // No-op for now - debugging disabled
    };
}

use crate::input_validation::{memmem, parse_der_length};
use const_oid::db::rfc5280::ID_CE_SUBJECT_ALT_NAME;
use vefas_types::{VefasError, VefasResult};
use x509_cert::{der::Decode, Certificate};

/// Comprehensive X.509 certificate validation
pub fn validate_x509_certificate(cert_der: &[u8], cert_index: usize) -> VefasResult<()> {
    // Minimum certificate size check
    if cert_der.len() < 100 {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} too short (minimum 100 bytes required)",
                cert_index
            ),
        ));
    }

    // Maximum certificate size check (prevent DoS)
    if cert_der.len() > 8192 {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} too large (maximum 8192 bytes allowed)",
                cert_index
            ),
        ));
    }

    // Validate DER encoding structure
    validate_der_structure(cert_der, cert_index)?;

    // Parse and validate X.509 certificate using x509-cert crate
    match Certificate::from_der(cert_der) {
        Ok(cert) => {
            // Validate certificate structure
            validate_certificate_structure(&cert, cert_index)?;

            // Validate certificate extensions
            validate_certificate_extensions(&cert, cert_index)?;

            Ok(())
        }
        Err(e) => Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} invalid X.509 structure: {:?}",
                cert_index, e
            ),
        )),
    }
}

/// Validate DER encoding structure
pub fn validate_der_structure(cert_der: &[u8], cert_index: usize) -> VefasResult<()> {
    // Check DER SEQUENCE tag
    if cert_der[0] != 0x30 {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} invalid DER encoding (expected SEQUENCE tag 0x30)",
                cert_index
            ),
        ));
    }

    // Validate DER length encoding
    let (declared_len, len_bytes) = parse_der_length(&cert_der[1..]).ok_or_else(|| {
        VefasError::invalid_input(
            "certificate_chain",
            &format!("Certificate {} invalid DER length encoding", cert_index),
        )
    })?;

    // Verify total length consistency
    let expected_total = 1 + len_bytes + declared_len;
    if expected_total != cert_der.len() {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} DER length mismatch: expected {}, got {}",
                cert_index,
                expected_total,
                cert_der.len()
            ),
        ));
    }

    Ok(())
}

/// Validate X.509 certificate structure
pub fn validate_certificate_structure(cert: &Certificate, cert_index: usize) -> VefasResult<()> {
    let tbs = &cert.tbs_certificate;

    // Validate version (should be v3 = 2)
    let version = &tbs.version;
    match version {
        x509_cert::Version::V1 | x509_cert::Version::V2 => {
            return Err(VefasError::invalid_input(
                "certificate_chain",
                &format!(
                    "Certificate {} uses obsolete version (v1/v2), v3 required",
                    cert_index
                ),
            ));
        }
        x509_cert::Version::V3 => {
            // Good - v3 is required for extensions
        }
    }

    // Validate serial number (must be present and reasonable size)
    let serial_bytes = tbs.serial_number.as_bytes();
    if serial_bytes.is_empty() {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!("Certificate {} missing serial number", cert_index),
        ));
    }
    if serial_bytes.len() > 20 {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} serial number too long (max 20 bytes)",
                cert_index
            ),
        ));
    }

    // Validate signature algorithm is supported
    validate_signature_algorithm(&tbs.signature, cert_index)?;

    // Validate public key algorithm is supported
    validate_public_key_algorithm(&tbs.subject_public_key_info, cert_index)?;

    Ok(())
}

/// Validate certificate extensions
pub fn validate_certificate_extensions(cert: &Certificate, cert_index: usize) -> VefasResult<()> {
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        let mut has_key_usage = false;
        let mut has_basic_constraints = false;
        let mut has_san = false;

        for ext in extensions {
            // Check for required extensions
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_KEY_USAGE {
                has_key_usage = true;
            } else if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                has_basic_constraints = true;
            } else if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
                has_san = true;
            }
        }

        // For leaf certificates (index 0), require KeyUsage and SubjectAltName
        if cert_index == 0 {
            if !has_key_usage {
                return Err(VefasError::invalid_input(
                    "certificate_chain",
                    "Leaf certificate missing required KeyUsage extension",
                ));
            }
            if !has_san {
                return Err(VefasError::invalid_input(
                    "certificate_chain",
                    "Leaf certificate missing required SubjectAltName extension",
                ));
            }
        }

        // For CA certificates, require BasicConstraints
        if cert_index > 0 && !has_basic_constraints {
            return Err(VefasError::invalid_input(
                "certificate_chain",
                &format!(
                    "CA certificate {} missing BasicConstraints extension",
                    cert_index
                ),
            ));
        }
    }

    Ok(())
}

/// Validate signature algorithm is supported
pub fn validate_signature_algorithm(
    sig_alg: &spki::AlgorithmIdentifierOwned,
    cert_index: usize,
) -> VefasResult<()> {
    // Only allow secure signature algorithms
    let oid_str = sig_alg.oid.to_string();
    match oid_str.as_str() {
        "1.2.840.113549.1.1.11" => Ok(()), // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12" => Ok(()), // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13" => Ok(()), // sha512WithRSAEncryption
        "1.2.840.10045.4.3.2" => Ok(()),   // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3" => Ok(()),   // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4" => Ok(()),   // ecdsa-with-SHA512
        _ => Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} uses unsupported signature algorithm: {}",
                cert_index, oid_str
            ),
        )),
    }
}

/// Validate public key algorithm is supported
pub fn validate_public_key_algorithm(
    pub_key_info: &spki::SubjectPublicKeyInfoOwned,
    cert_index: usize,
) -> VefasResult<()> {
    let oid_str = pub_key_info.algorithm.oid.to_string();
    match oid_str.as_str() {
        "1.2.840.113549.1.1.1" => Ok(()), // rsaEncryption
        "1.2.840.10045.2.1" => Ok(()),    // ecPublicKey
        _ => Err(VefasError::invalid_input(
            "certificate_chain",
            &format!(
                "Certificate {} uses unsupported public key algorithm: {}",
                cert_index, oid_str
            ),
        )),
    }
}

/// Validate certificate chain structure and basic chain of trust
pub fn validate_certificate_chain_structure(cert_chain: &[Vec<u8>]) -> VefasResult<()> {
    if cert_chain.is_empty() {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            "Empty certificate chain",
        ));
    }

    if cert_chain.len() > 10 {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            "Certificate chain too long (maximum 10 certificates allowed)",
        ));
    }

    // Parse all certificates first
    let mut certificates = Vec::new();
    for (i, cert_der) in cert_chain.iter().enumerate() {
        match Certificate::from_der(cert_der) {
            Ok(cert) => certificates.push(cert),
            Err(_) => {
                return Err(VefasError::invalid_input(
                    "certificate_chain",
                    &format!("Failed to parse certificate {} in chain", i),
                ));
            }
        }
    }

    // Validate chain structure (leaf → intermediate(s) → root)
    for i in 0..certificates.len() {
        let cert = &certificates[i];

        if i == 0 {
            // Leaf certificate validation
            validate_leaf_certificate(cert)?;
        } else {
            // CA certificate validation
            validate_ca_certificate(cert, i)?;
        }
    }

    Ok(())
}

/// Validate leaf certificate properties
pub fn validate_leaf_certificate(cert: &Certificate) -> VefasResult<()> {
    // Check that it's not a CA certificate
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        for ext in extensions {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                // If BasicConstraints is present, cA MUST be false for leaf certs
                // For now, we'll just warn - in production this should be enforced
                // based on proper ASN.1 parsing of the extension
            }
        }
    }

    Ok(())
}

/// Validate CA certificate properties
pub fn validate_ca_certificate(cert: &Certificate, cert_index: usize) -> VefasResult<()> {
    // CA certificates should have BasicConstraints extension with cA=true
    // This is a simplified check - full implementation would parse the extension properly
    if let Some(extensions) = &cert.tbs_certificate.extensions {
        let mut has_basic_constraints = false;

        for ext in extensions {
            if ext.extn_id == const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS {
                has_basic_constraints = true;
                break;
            }
        }

        if !has_basic_constraints {
            return Err(VefasError::invalid_input(
                "certificate_chain",
                &format!(
                    "CA certificate {} missing BasicConstraints extension",
                    cert_index
                ),
            ));
        }
    }

    Ok(())
}

/// Check if certificate matches the expected domain name
pub fn domain_matches(cert_der: &[u8], expected_domain: &str) -> VefasResult<bool> {
    if expected_domain.is_empty() {
        return Ok(false);
    }

    // Try proper X.509 parsing first
    if let Ok(cert) = Certificate::from_der(cert_der) {
        if let Some(found) = match_domain_x509(&cert, expected_domain) {
            return Ok(found);
        }
    }

    // Fallback: byte search for deterministic behavior if parsing unsupported
    Ok(domain_matches_fallback(cert_der, expected_domain))
}

/// Match domain using proper X.509 parsing
fn match_domain_x509(cert: &Certificate, expected_domain: &str) -> Option<bool> {
    let host = to_lower_ascii(expected_domain);

    // SubjectAltName DNSNames
    if let Some(dns_names) = parse_san_dns_names(cert) {
        for dns in dns_names {
            if dns_matches(&dns, &host) {
                return Some(true);
            }
        }
        return Some(false);
    }

    // CN fallback intentionally omitted (SAN is required in RFC 6125)
    // return false if SAN present but no match
    Some(false)
}

/// Parse DNS names from SubjectAltName extension
fn parse_san_dns_names(cert: &Certificate) -> Option<Vec<String>> {
    let exts = cert.tbs_certificate.extensions.as_ref()?;

    for ext in exts {
        if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
            let bytes = ext.extn_value.as_bytes();

            // Expect a DER SEQUENCE (0x30) of GeneralName
            if bytes.is_empty() || bytes[0] != 0x30 {
                return Some(Vec::new());
            }

            let mut i = 1usize;
            let (seq_len, nlen) = der_read_len(bytes.get(i..))?;
            i += nlen;

            if i + seq_len > bytes.len() {
                return Some(Vec::new());
            }

            let end = i + seq_len;
            let mut out = Vec::new();

            while i < end {
                if i >= bytes.len() {
                    break;
                }

                let tag = bytes[i];
                i += 1;

                let (len, nlen2) = der_read_len(bytes.get(i..))?;
                i += nlen2;

                if i + len > bytes.len() {
                    break;
                }

                let val = &bytes[i..i + len];
                i += len;

                // dNSName is [2] IA5String => tag 0x82 (context-specific primitive, number 2)
                if tag == 0x82 {
                    if let Ok(s) = core::str::from_utf8(val) {
                        out.push(s.to_ascii_lowercase());
                    }
                }
            }

            return Some(out);
        }
    }

    None
}

/// DER length reading helper
fn der_read_len(slice: Option<&[u8]>) -> Option<(usize, usize)> {
    let data = slice?;
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first & 0x80 == 0 {
        Some(((first & 0x7F) as usize, 1))
    } else {
        let num = (first & 0x7F) as usize;
        if num == 0 || num > 4 || data.len() < 1 + num {
            return None;
        }

        let mut len = 0usize;
        for &b in &data[1..1 + num] {
            len = (len << 8) | (b as usize);
        }
        Some((len, 1 + num))
    }
}

/// DNS name matching with wildcard support
fn dns_matches(cert_name: &str, host: &str) -> bool {
    if cert_name.starts_with("*.") {
        // Wildcard only in left-most label, and must match a single label
        if let Some(dot) = host.find('.') {
            let suffix = &host[dot + 1..];
            return cert_name.len() > 2 && &cert_name[2..] == suffix;
        }
        return false;
    }
    cert_name == host
}

/// Convert string to lowercase ASCII
fn to_lower_ascii(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Fallback domain matching using byte search
fn domain_matches_fallback(cert_der: &[u8], expected_domain: &str) -> bool {
    let domain_lower = expected_domain.as_bytes();
    if domain_lower.is_empty() {
        return false;
    }

    if memmem(cert_der, domain_lower) {
        return true;
    }

    // Check wildcard pattern
    if let Some(idx) = expected_domain.find('.') {
        let suffix = &expected_domain[idx + 1..];
        let mut wildcard = Vec::with_capacity(2 + suffix.len());
        wildcard.extend_from_slice(b"*.");
        wildcard.extend_from_slice(suffix.as_bytes());
        if memmem(cert_der, &wildcard) {
            return true;
        }
    }

    false
}

/// Validate complete certificate message structure
pub fn validate_certificate_message(cert_msg: &[u8], cert_chain: &[Vec<u8>]) -> VefasResult<()> {
    // Validate TLS record and handshake header
    let (hs_type, hs_len, _body) = crate::tls_parser::parse_handshake_header(cert_msg)
        .ok_or_else(|| VefasError::invalid_input("certificate", "Malformed Certificate message"))?;

    if hs_type != 0x0b {
        return Err(VefasError::invalid_input(
            "certificate",
            "Unexpected handshake type (expected Certificate)",
        ));
    }

    // Verify certificate chain is not empty
    if cert_chain.is_empty() {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            "Empty certificate chain",
        ));
    }

    // Enhanced X.509 certificate validation
    for (i, cert) in cert_chain.iter().enumerate() {
        validate_x509_certificate(cert, i)?;
    }

    // Validate certificate chain structure
    validate_certificate_chain_structure(cert_chain)?;

    // Basic length sanity
    if hs_len == 0 {
        return Err(VefasError::invalid_input(
            "certificate",
            "Empty handshake body",
        ));
    }

    Ok(())
}

/// Validate certificate domain binding
pub fn validate_certificate_domain_binding(
    cert_chain: &[Vec<u8>],
    domain: &str,
) -> VefasResult<()> {
    if let Some(leaf) = cert_chain.first() {
        if !domain_matches(leaf, domain)? {
            return Err(VefasError::invalid_input(
                "certificate",
                "Leaf certificate does not match domain",
            ));
        }
    } else {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            "Empty certificate chain",
        ));
    }

    Ok(())
}

/// Verify certificate signature using issuer's public key
///
/// This function extracts the TBS (to-be-signed) certificate, signature algorithm,
/// and signature value, then verifies using the appropriate algorithm from the crypto provider.
///
/// # Arguments
/// * `crypto` - Cryptographic provider implementing signature verification
/// * `cert_der` - DER-encoded certificate to verify
/// * `issuer_der` - DER-encoded issuer certificate containing public key
///
/// # Returns
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_certificate_signature<C>(
    crypto: &C,
    cert_der: &[u8],
    issuer_der: &[u8],
) -> VefasResult<()>
where
    C: crate::traits::Signature + crate::traits::Hash,
{
    debug_print!("🔍 Starting certificate signature verification");
    debug_print!("   Certificate DER length: {}", cert_der.len());
    debug_print!("   Issuer DER length: {}", issuer_der.len());

    // Parse both certificates
    let cert = Certificate::from_der(cert_der).map_err(|e| {
        #[cfg(feature = "std")]
        debug_print!("❌ Failed to parse certificate: {:?}", e);
        VefasError::invalid_input(
            "certificate",
            &format!("Failed to parse certificate: {:?}", e),
        )
    })?;

    let issuer_cert = Certificate::from_der(issuer_der).map_err(|e| {
        #[cfg(feature = "std")]
        debug_print!("❌ Failed to parse issuer certificate: {:?}", e);
        VefasError::invalid_input(
            "issuer_certificate",
            &format!("Failed to parse issuer: {:?}", e),
        )
    })?;

    #[cfg(feature = "std")]
    debug_print!("✅ Successfully parsed both certificates");

    // Extract TBS certificate (the signed data)
    let tbs_der = extract_tbs_certificate_der(cert_der)?;
    #[cfg(feature = "std")]
    debug_print!("   TBS certificate length: {}", tbs_der.len());
    #[cfg(feature = "std")]
    debug_print!("   TBS first 10 bytes: {:02x?}", &tbs_der[..10.min(tbs_der.len())]);

    // Extract issuer's public key
    let issuer_public_key = &issuer_cert.tbs_certificate.subject_public_key_info;
    let pub_key_bytes = issuer_public_key
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| {
            #[cfg(feature = "std")]
            debug_print!("❌ Missing public key bits");
            VefasError::invalid_input("public_key", "Missing public key bits")
        })?;

    #[cfg(feature = "std")]
    debug_print!("   Public key length: {}", pub_key_bytes.len());
    #[cfg(feature = "std")]
    debug_print!("   Public key first 10 bytes: {:02x?}", &pub_key_bytes[..10.min(pub_key_bytes.len())]);

    // Extract signature algorithm and value
    let sig_alg = &cert.signature_algorithm;
    let signature = cert
        .signature
        .as_bytes()
        .ok_or_else(|| {
            #[cfg(feature = "std")]
            debug_print!("❌ Missing signature value");
            VefasError::invalid_input("certificate", "Missing signature value")
        })?;

    #[cfg(feature = "std")]
    debug_print!("   Signature algorithm OID: {}", sig_alg.oid);
    #[cfg(feature = "std")]
    debug_print!("   Signature length: {}", signature.len());
    #[cfg(feature = "std")]
    debug_print!("   Signature first 10 bytes: {:02x?}", &signature[..10.min(signature.len())]);

    // Verify based on algorithm
    verify_signature_by_algorithm(crypto, sig_alg, issuer_public_key, tbs_der, signature)
}

/// Extract TBS certificate bytes from full certificate DER
fn extract_tbs_certificate_der(cert_der: &[u8]) -> VefasResult<&[u8]> {
    // Certificate ::= SEQUENCE {
    //   tbsCertificate       TBSCertificate,  <-- We want this
    //   signatureAlgorithm   AlgorithmIdentifier,
    //   signature            BIT STRING
    // }

    if cert_der.len() < 4 || cert_der[0] != 0x30 {
        return Err(VefasError::invalid_input(
            "certificate",
            "Invalid DER structure",
        ));
    }

    // Skip SEQUENCE tag and length
    let (_outer_len, outer_len_bytes) = parse_der_length(&cert_der[1..])
        .ok_or_else(|| VefasError::invalid_input("certificate", "Invalid DER length"))?;

    let tbs_start = 1 + outer_len_bytes;
    if tbs_start >= cert_der.len() || cert_der[tbs_start] != 0x30 {
        return Err(VefasError::invalid_input(
            "certificate",
            "Missing TBS certificate",
        ));
    }

    // TBS is a SEQUENCE, get its length
    let (tbs_len, tbs_len_bytes) = parse_der_length(&cert_der[tbs_start + 1..])
        .ok_or_else(|| VefasError::invalid_input("certificate", "Invalid TBS length"))?;

    let tbs_end = tbs_start + 1 + tbs_len_bytes + tbs_len;
    if tbs_end > cert_der.len() {
        return Err(VefasError::invalid_input(
            "certificate",
            "TBS certificate truncated",
        ));
    }

    Ok(&cert_der[tbs_start..tbs_end])
}

/// Test helper to expose TBS extraction
#[cfg(test)]
pub fn extract_tbs_certificate_der_for_test(cert_der: &[u8]) -> VefasResult<Vec<u8>> {
    Ok(extract_tbs_certificate_der(cert_der)?.to_vec())
}

/// Verify signature based on algorithm OID
fn verify_signature_by_algorithm<C>(
    crypto: &C,
    sig_alg: &spki::AlgorithmIdentifierOwned,
    issuer_public_key: &spki::SubjectPublicKeyInfoOwned,
    message: &[u8],
    signature: &[u8],
) -> VefasResult<()>
where
    C: crate::traits::Signature + crate::traits::Hash,
{
    let sig_oid = sig_alg.oid.to_string();
    #[cfg(feature = "std")]
    debug_print!("🔐 Verifying signature with algorithm: {}", sig_oid);

    match sig_oid.as_str() {
        // RSA with SHA-256 (PKCS#1 v1.5)
        "1.2.840.113549.1.1.11" => {
            #[cfg(feature = "std")]
            debug_print!("   Using RSA PKCS#1 SHA-256 verification");
            
            // RSA PKCS#1 expects the original message, not the hash
            // The signature function will hash it internally
            let pub_key_der = issuer_public_key
                .subject_public_key
                .as_bytes()
                .ok_or_else(|| {
                    #[cfg(feature = "std")]
                    debug_print!("❌ Missing public key bits for RSA verification");
                    VefasError::invalid_input("public_key", "Missing public key bits")
                })?;

            #[cfg(feature = "std")]
            debug_print!("   Calling rsa_pkcs1_sha256_verify with:");
            #[cfg(feature = "std")]
            debug_print!("     - Public key length: {}", pub_key_der.len());
            #[cfg(feature = "std")]
            debug_print!("     - Message length: {}", message.len());
            #[cfg(feature = "std")]
            debug_print!("     - Signature length: {}", signature.len());

            let result = crypto.rsa_pkcs1_sha256_verify(pub_key_der, message, signature);
            #[cfg(feature = "std")]
            debug_print!("   RSA verification result: {}", result);

            if result {
                #[cfg(feature = "std")]
                debug_print!("✅ RSA PKCS#1 SHA-256 signature verification successful");
                Ok(())
            } else {
                #[cfg(feature = "std")]
                debug_print!("❌ RSA PKCS#1 SHA-256 signature verification failed");
                Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::SignatureVerificationFailed,
                    "RSA PKCS#1 SHA-256 signature verification failed",
                ))
            }
        }
        // ECDSA with SHA-256 (P-256)
        "1.2.840.10045.4.3.2" => {
            #[cfg(feature = "std")]
            debug_print!("   Using ECDSA P-256 SHA-256 verification");

            // Extract P-256 public key (65 bytes uncompressed)
            let pub_key_bytes =
                issuer_public_key
                    .subject_public_key
                    .as_bytes()
                    .ok_or_else(|| {
                        #[cfg(feature = "std")]
                        debug_print!("❌ Missing public key bits for ECDSA verification");
                        VefasError::invalid_input("public_key", "Missing public key bits")
                    })?;

            #[cfg(feature = "std")]
            debug_print!("   Public key length: {}", pub_key_bytes.len());

            if pub_key_bytes.len() != 65 || pub_key_bytes[0] != 0x04 {
                #[cfg(feature = "std")]
                debug_print!("❌ Invalid P-256 public key format: length={}, first_byte=0x{:02x}",
                    pub_key_bytes.len(), pub_key_bytes[0]);
                return Err(VefasError::invalid_input(
                    "public_key",
                    "Invalid P-256 public key format",
                ));
            }

            let mut pub_key = [0u8; 65];
            pub_key.copy_from_slice(pub_key_bytes);

            #[cfg(feature = "std")]
            debug_print!("   Calling p256_verify with original message");
            // ECDSA verification expects the original message, not the hash
            // The p256_verify function will hash it internally
            let result = crypto.p256_verify(&pub_key, message, signature);
            #[cfg(feature = "std")]
            debug_print!("   ECDSA verification result: {}", result);

            if result {
                #[cfg(feature = "std")]
                debug_print!("✅ ECDSA P-256 SHA-256 signature verification successful");
                Ok(())
            } else {
                #[cfg(feature = "std")]
                debug_print!("❌ ECDSA P-256 SHA-256 signature verification failed");
                Err(VefasError::crypto_error(
                    vefas_types::errors::CryptoErrorType::SignatureVerificationFailed,
                    "ECDSA P-256 SHA-256 signature verification failed",
                ))
            }
        }
        // ECDSA with SHA-384 (P-384)
        "1.2.840.10045.4.3.3" => {
            #[cfg(feature = "std")]
            debug_print!("   ECDSA P-384 SHA-384 not yet implemented (H-4 priority)");
            Err(VefasError::invalid_input(
                "signature_algorithm",
                "ECDSA P-384 verification not yet implemented",
            ))
        }
        // ECDSA with SHA-512 (P-521)
        "1.2.840.10045.4.3.4" => {
            #[cfg(feature = "std")]
            debug_print!("   ECDSA P-521 SHA-512 not yet implemented (H-4 priority)");
            Err(VefasError::invalid_input(
                "signature_algorithm",
                "ECDSA P-521 verification not yet implemented",
            ))
        }
        _ => {
            #[cfg(feature = "std")]
            debug_print!("❌ Unsupported signature algorithm: {}", sig_oid);
            Err(VefasError::invalid_input(
                "signature_algorithm",
                &format!("Unsupported signature algorithm: {}", sig_oid),
            ))
        }
    }
}

/// Verify all signatures in a certificate chain
///
/// Verifies that each certificate (except the root) is signed by the next certificate in the chain.
///
/// # Arguments
/// * `crypto` - Cryptographic provider
/// * `cert_chain` - Certificate chain from leaf to root
///
/// # Returns
/// Ok(()) if all signatures are valid
pub fn verify_certificate_chain_signatures<C>(crypto: &C, cert_chain: &[Vec<u8>]) -> VefasResult<()>
where
    C: crate::traits::VefasCrypto,
{
    if cert_chain.is_empty() {
        return Err(VefasError::invalid_input(
            "certificate_chain",
            "Empty certificate chain",
        ));
    }

    // Verify each certificate (except root) is signed by the next one
    for i in 0..cert_chain.len() - 1 {
        let cert = &cert_chain[i];
        let issuer = &cert_chain[i + 1];

        verify_certificate_signature(crypto, cert, issuer).map_err(|e| {
            VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::SignatureVerificationFailed,
                &format!("Certificate {} signature verification failed: {:?}", i, e),
            )
        })?;
    }

    // For root certificate (last in chain), it should be self-signed
    if cert_chain.len() > 0 {
        let root = cert_chain.last().unwrap();
        verify_certificate_signature(crypto, root, root).map_err(|e| {
            VefasError::crypto_error(
                vefas_types::errors::CryptoErrorType::SignatureVerificationFailed,
                &format!(
                    "Root certificate self-signature verification failed: {:?}",
                    e
                ),
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn validate_der_structure_valid() {
        // Simple valid DER SEQUENCE
        let der = [0x30, 0x03, 0x01, 0x02, 0x03]; // SEQUENCE { 1, 2, 3 }
        let result = validate_der_structure(&der, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_der_structure_invalid_tag() {
        // Invalid tag (not SEQUENCE)
        let der = [0x31, 0x03, 0x01, 0x02, 0x03]; // SET instead of SEQUENCE
        let result = validate_der_structure(&der, 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_der_structure_length_mismatch() {
        // Length mismatch
        let der = [0x30, 0x05, 0x01, 0x02]; // Claims 5 bytes but only has 2
        let result = validate_der_structure(&der, 0);
        assert!(result.is_err());
    }

    #[test]
    fn dns_matches_exact() {
        assert!(dns_matches("example.com", "example.com"));
        assert!(!dns_matches("example.com", "other.com"));
    }

    #[test]
    fn dns_matches_wildcard() {
        assert!(dns_matches("*.example.com", "api.example.com"));
        assert!(dns_matches("*.example.com", "www.example.com"));
        assert!(!dns_matches("*.example.com", "example.com")); // Wildcard doesn't match base domain
        assert!(!dns_matches("*.example.com", "sub.api.example.com")); // Wildcard only matches one label
    }

    #[test]
    fn domain_matches_fallback_exact() {
        let cert_der = b"random\x30DERbytes...example.com...more";
        assert!(domain_matches_fallback(cert_der, "example.com"));
    }

    #[test]
    fn domain_matches_fallback_wildcard() {
        let cert_der = b"...*.example.com...";
        assert!(domain_matches_fallback(cert_der, "api.example.com"));
    }

    #[test]
    fn domain_matches_fallback_no_match() {
        let cert_der = b"no domains here";
        assert!(!domain_matches_fallback(cert_der, "example.com"));
    }

    #[test]
    fn validate_certificate_chain_structure_empty() {
        let chain: Vec<Vec<u8>> = vec![];
        let result = validate_certificate_chain_structure(&chain);
        assert!(result.is_err());
    }

    #[test]
    fn validate_certificate_chain_structure_too_long() {
        let chain: Vec<Vec<u8>> = vec![vec![0u8; 100]; 15]; // 15 certificates
        let result = validate_certificate_chain_structure(&chain);
        assert!(result.is_err());
    }

    #[test]
    fn validate_x509_certificate_too_short() {
        let cert = vec![0u8; 50]; // Too short
        let result = validate_x509_certificate(&cert, 0);
        assert!(result.is_err());
    }

    #[test]
    fn validate_x509_certificate_too_large() {
        let cert = vec![0u8; 10000]; // Too large
        let result = validate_x509_certificate(&cert, 0);
        assert!(result.is_err());
    }
}
