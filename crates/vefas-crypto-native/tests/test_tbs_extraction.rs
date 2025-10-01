//! Test TBS certificate extraction

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

#[test]
fn test_tbs_extraction() {
    let crypto = NativeCryptoProvider::new();
    
    // Load RSA certificate
    let cert_pem = fs::read("../../fixtures/certificates/rsa2048.crt").unwrap();
    let cert_der = pem_to_der(&cert_pem).unwrap();
    
    println!("Certificate DER length: {}", cert_der.len());
    println!("Certificate DER first 10 bytes: {:02x?}", &cert_der[..10]);
    
    // Test certificate verification (which uses TBS extraction internally)
    match verify_certificate_signature(&crypto, &cert_der, &cert_der) {
        Ok(_) => {
            println!("✅ Certificate verification successful");
        }
        Err(e) => {
            println!("❌ Certificate verification failed: {:?}", e);
            
            // This tells us if the issue is with TBS extraction or signature verification
            let error_msg = format!("{:?}", e);
            if error_msg.contains("Failed to parse certificate") {
                println!("Issue: Certificate parsing failed");
            } else if error_msg.contains("signature verification failed") {
                println!("Issue: Signature verification failed (TBS extraction likely OK)");
            } else {
                println!("Issue: Other error");
            }
        }
    }
}
