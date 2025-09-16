//! Test to verify that our cryptographic signature verification is working correctly
//! This helps isolate whether the issue is with our crypto implementation or the certificate data

use zktls_crypto::native::NativeCryptoProvider;
use zktls_crypto::traits::Signature;

#[test]
fn test_ecdsa_signature_verification_basic() {
    let crypto_provider = NativeCryptoProvider::new();
    
    // Generate a test keypair 
    let (private_key, public_key) = crypto_provider.p256_generate_keypair().unwrap();
    
    println!("Generated keypair - private: {} bytes, public: {} bytes", private_key.len(), public_key.len());
    
    // Test message
    let message = b"Hello, zkTLS!";
    
    // Sign the message
    let signature = match crypto_provider.p256_sign(&private_key, message) {
        Ok(sig) => {
            println!("Generated signature: {} bytes", sig.len());
            sig
        },
        Err(e) => {
            panic!("Failed to sign message: {:?}", e);
        }
    };
    
    // Verify the signature
    let is_valid = crypto_provider.p256_verify(&public_key, message, &signature).unwrap();
    
    assert!(is_valid, "Generated signature should be valid");
    
    // Test with invalid signature
    let mut invalid_signature = signature.clone();
    invalid_signature[0] ^= 0xFF; // Flip some bits
    
    // Tampered signature should either return false or error (both are acceptable)
    let is_valid_invalid = crypto_provider.p256_verify(&public_key, message, &invalid_signature);
    match is_valid_invalid {
        Ok(false) => {
            // Signature returned false - acceptable
        },
        Err(_) => {
            // Signature verification failed - also acceptable for tampered data
        },
        Ok(true) => {
            panic!("Tampered signature should not verify as valid");
        }
    }
    
    println!("✓ Basic ECDSA signature verification works correctly");
}

#[test]
fn test_ecdsa_with_certificate_like_data() {
    let crypto_provider = NativeCryptoProvider::new();
    
    // Generate a test keypair 
    let (private_key, public_key) = crypto_provider.p256_generate_keypair().unwrap();
    
    // Create some test data that resembles TBS certificate data
    // This simulates the structure we see in the debug output
    let tbs_like_data = [
        0x30, 0x82, 0x01, 0x96, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x51, 0x4f, 0xd9, 0x01, 
        0x18, 0xc3, 0xfe, 0x59, 0x38, 0x12, 0xc9, 0xe6, 0x3c, 0x9f, 0x19, 0x75, 0x54, 0xb7, 0x55, 
        0x65, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x45, 
        0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x19, 
        0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x10, 0x42, 0x79, 0x74, 0x65, 0x42, 0x69,
    ];
    
    // Sign the TBS-like data (this will hash it internally)
    let signature = crypto_provider.p256_sign(&private_key, &tbs_like_data).unwrap();
    println!("Generated signature: {} bytes", signature.len());
    
    // Verify the signature (this will also hash the data internally)
    let is_valid = crypto_provider.p256_verify(&public_key, &tbs_like_data, &signature).unwrap();
    println!("Signature verification result: {}", is_valid);
    
    assert!(is_valid, "Signature on TBS-like data should be valid");
    
    println!("✓ ECDSA signature verification with certificate-like data works correctly");
    println!("  Public key length: {}", public_key.len());
    println!("  Signature length: {}", signature.len());
    println!("  TBS data length: {}", tbs_like_data.len());
}