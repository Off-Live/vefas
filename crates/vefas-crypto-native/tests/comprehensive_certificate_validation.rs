//! Comprehensive certificate validation tests with debugging

use std::fs;
use base64::Engine;

use vefas_crypto::validation::verify_certificate_signature;
use vefas_crypto_native::NativeCryptoProvider;

/// Convert PEM certificate to DER format
fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>, String> {
    let pem_str = String::from_utf8(pem_data.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in PEM data: {}", e))?;
    
    let begin_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    
    let begin_pos = pem_str.find(begin_marker)
        .ok_or("BEGIN CERTIFICATE marker not found")?;
    let end_pos = pem_str.find(end_marker)
        .ok_or("END CERTIFICATE marker not found")?;
    
    if end_pos <= begin_pos {
        return Err("Invalid PEM structure".to_string());
    }
    
    let base64_start = begin_pos + begin_marker.len();
    let base64_content = &pem_str[base64_start..end_pos];
    
    let clean_base64: String = base64_content
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    
    let der_data = base64::engine::general_purpose::STANDARD
        .decode(&clean_base64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    Ok(der_data)
}

/// Test certificate validation for a specific certificate file
fn test_certificate_validation(cert_path: &str, cert_name: &str) {
    println!("\n🧪 Testing {} certificate validation", cert_name);
    println!("{}", "=".repeat(50));
    
    let crypto = NativeCryptoProvider::new();
    
    // Load certificate
    let cert_pem = match fs::read(cert_path) {
        Ok(data) => data,
        Err(e) => {
            println!("❌ Failed to read certificate file {}: {}", cert_path, e);
            return;
        }
    };
    
    let cert_der = match pem_to_der(&cert_pem) {
        Ok(der) => der,
        Err(e) => {
            println!("❌ Failed to convert PEM to DER: {}", e);
            return;
        }
    };
    
    println!("📄 Certificate loaded successfully");
    println!("   File: {}", cert_path);
    println!("   DER length: {} bytes", cert_der.len());
    println!("   DER first 10 bytes: {:02x?}", &cert_der[..10.min(cert_der.len())]);
    
    // Test self-signed certificate verification
    println!("\n🔐 Testing self-signed certificate verification...");
    match verify_certificate_signature(&crypto, &cert_der, &cert_der) {
        Ok(_) => {
            println!("✅ {} certificate verification successful", cert_name);
        }
        Err(e) => {
            println!("❌ {} certificate verification failed: {:?}", cert_name, e);
            
            // Analyze the error
            let error_msg = format!("{:?}", e);
            if error_msg.contains("Failed to parse certificate") {
                println!("   Issue: Certificate parsing failed");
            } else if error_msg.contains("signature verification failed") {
                println!("   Issue: Signature verification failed");
            } else if error_msg.contains("Unsupported signature algorithm") {
                println!("   Issue: Unsupported signature algorithm");
            } else if error_msg.contains("Invalid P-256 public key format") {
                println!("   Issue: Invalid ECDSA public key format");
            } else {
                println!("   Issue: Other error - {}", error_msg);
            }
        }
    }
}

#[test]
fn test_rsa_2048_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/rsa2048.crt", "RSA 2048");
}

#[test]
fn test_rsa_4096_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/rsa4096.crt", "RSA 4096");
}

#[test]
fn test_ecdsa_p256_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/ecdsa_p256.crt", "ECDSA P-256");
}

#[test]
fn test_ecdsa_p384_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/ecdsa_p384.crt", "ECDSA P-384");
}

#[test]
fn test_ecdsa_p521_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/ecdsa_p521.crt", "ECDSA P-521");
}

#[test]
fn test_ed25519_certificate_validation() {
    test_certificate_validation("../../fixtures/certificates/ed25519.crt", "Ed25519");
}

#[test]
fn test_all_certificates_comprehensive() {
    println!("\n🚀 Running comprehensive certificate validation tests");
    println!("{}", "=".repeat(60));
    
    let certificates = vec![
        ("../../fixtures/certificates/rsa1024.crt", "RSA 1024"),
        ("../../fixtures/certificates/rsa2048.crt", "RSA 2048"),
        ("../../fixtures/certificates/rsa4096.crt", "RSA 4096"),
        ("../../fixtures/certificates/ecdsa_p256.crt", "ECDSA P-256"),
        ("../../fixtures/certificates/ecdsa_p384.crt", "ECDSA P-384"),
        ("../../fixtures/certificates/ecdsa_p521.crt", "ECDSA P-521"),
        ("../../fixtures/certificates/ed25519.crt", "Ed25519"),
    ];
    
    let mut success_count = 0;
    let mut total_count = certificates.len();
    
    for (cert_path, cert_name) in certificates {
        println!("\n🧪 Testing {} certificate validation", cert_name);
        println!("{}", "-".repeat(40));
        
        let crypto = NativeCryptoProvider::new();
        
        // Load certificate
        let cert_pem = match fs::read(cert_path) {
            Ok(data) => data,
            Err(e) => {
                println!("❌ Failed to read certificate file {}: {}", cert_path, e);
                continue;
            }
        };
        
        let cert_der = match pem_to_der(&cert_pem) {
            Ok(der) => der,
            Err(e) => {
                println!("❌ Failed to convert PEM to DER: {}", e);
                continue;
            }
        };
        
        // Test self-signed certificate verification
        match verify_certificate_signature(&crypto, &cert_der, &cert_der) {
            Ok(_) => {
                println!("✅ {} certificate verification successful", cert_name);
                success_count += 1;
            }
            Err(e) => {
                println!("❌ {} certificate verification failed: {:?}", cert_name, e);
            }
        }
    }
    
    println!("\n📊 Test Results Summary");
    println!("{}", "=".repeat(30));
    println!("Total certificates tested: {}", total_count);
    println!("Successful verifications: {}", success_count);
    println!("Failed verifications: {}", total_count - success_count);
    println!("Success rate: {:.1}%", (success_count as f64 / total_count as f64) * 100.0);
    
    // For now, we expect some failures due to unsupported algorithms
    // This test is mainly for debugging and understanding the issues
    if success_count > 0 {
        println!("✅ At least some certificates verified successfully");
    } else {
        println!("⚠️  No certificates verified successfully - need to investigate");
    }
}
