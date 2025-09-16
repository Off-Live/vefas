//! Unit tests for real network communication
//! 
//! These tests follow TDD methodology and test real network operations
//! using SP1 precompiles and actual TLS 1.3 handshake implementation.

use zktls_core::{
    network::{NetworkClient, RealNetworkProvider, NetworkProvider},
    http::HttpRequest,
    errors::ZkTlsResult,
};
use alloc::string::ToString;

#[test]
fn test_tls_handshake_with_real_server() {
    // This test will fail initially (TDD Red phase)
    // It tests a complete TLS 1.3 handshake with real server
    let mut client = NetworkClient::new("httpbin.org", 443);
    
    // Establish real TLS connection
    let result = client.establish_tls_connection();
    assert!(result.is_ok(), "TLS handshake should succeed");
    
    // Verify connection state
    assert!(client.is_connected(), "Client should be connected after handshake");
}

#[test]
fn test_http_request_encryption() {
    // Test real HTTP request encryption using derived TLS keys
    let mut client = NetworkClient::new("httpbin.org", 443);
    client.establish_tls_connection().unwrap();
    
    let request = HttpRequest::get("/get", "httpbin.org").unwrap();
    let encrypted_request = client.encrypt_http_request(&request).unwrap();
    
    // Verify request is properly encrypted
    assert!(!encrypted_request.is_empty(), "Encrypted request should not be empty");
    assert_ne!(encrypted_request, request.to_bytes(), "Encrypted request should differ from plaintext");
}

#[test]
fn test_http_response_decryption() {
    // Test real HTTP response decryption
    let mut client = NetworkClient::new("httpbin.org", 443);
    client.establish_tls_connection().unwrap();
    
    let request = HttpRequest::get("/get", "httpbin.org").unwrap();
    let response = client.send_http_request(&request).unwrap();
    
    // Verify response is properly decrypted and parsed
    assert!(response.is_success(), "HTTP response should indicate success");
    assert!(!response.body().is_empty(), "Response body should not be empty");
}

#[test]
fn test_certificate_validation() {
    // Test real X.509 certificate chain validation
    let mut client = NetworkClient::new("httpbin.org", 443);
    let result = client.validate_server_certificate();
    
    assert!(result.is_ok(), "Certificate validation should succeed for valid server");
}

#[test]
fn test_key_derivation_using_sp1_precompiles() {
    // Test HKDF key derivation using SP1 precompiles
    let mut client = NetworkClient::new("httpbin.org", 443);
    client.establish_tls_connection().unwrap();
    
    let application_keys = client.derive_application_keys().unwrap();
    
    // Verify keys are properly derived
    assert!(!application_keys.client_key.is_empty(), "Client key should be derived");
    assert!(!application_keys.server_key.is_empty(), "Server key should be derived");
    assert_eq!(application_keys.client_key.len(), 32, "Client key should be 32 bytes");
    assert_eq!(application_keys.server_key.len(), 32, "Server key should be 32 bytes");
}

#[test]
fn test_network_provider_real_implementation() {
    // Test real network provider implementation
    let mut provider = RealNetworkProvider::new();
    
    // Test connection establishment
    let result = provider.connect("httpbin.org", 443);
    assert!(result.is_ok(), "Real network connection should succeed");
    
    // Test data transmission
    let test_data = b"GET /get HTTP/1.1\r\nHost: httpbin.org\r\n\r\n";
    let send_result = provider.send(test_data);
    assert!(send_result.is_ok(), "Data transmission should succeed");
    
    // Test data reception
    let mut buffer = [0u8; 4096];
    let receive_result = provider.receive(&mut buffer);
    assert!(receive_result.is_ok(), "Data reception should succeed");
    
    // Test connection cleanup
    let close_result = provider.close();
    assert!(close_result.is_ok(), "Connection cleanup should succeed");
}

#[test]
fn test_deterministic_operations_for_zkvm() {
    // Test that operations are deterministic for zkVM proof generation
    let mut client1 = NetworkClient::new("httpbin.org", 443);
    let mut client2 = NetworkClient::new("httpbin.org", 443);
    
    // Both clients should produce identical results
    client1.establish_tls_connection().unwrap();
    client2.establish_tls_connection().unwrap();
    
    let keys1 = client1.derive_application_keys().unwrap();
    let keys2 = client2.derive_application_keys().unwrap();
    
    assert_eq!(keys1.client_key, keys2.client_key, "Client keys should be identical");
    assert_eq!(keys1.server_key, keys2.server_key, "Server keys should be identical");
}

#[test]
fn test_sp1_precompile_integration() {
    // Test integration with SP1 precompiles
    let mut client = NetworkClient::new("httpbin.org", 443);
    
    // Test SHA-256 precompile usage
    let hash_result = client.compute_sha256(b"test data");
    assert!(hash_result.is_ok(), "SHA-256 precompile should work");
    assert_eq!(hash_result.unwrap().len(), 32, "SHA-256 should produce 32-byte hash");
    
    // Test AES-GCM precompile usage
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let plaintext = b"test message";
    
    let encrypt_result = client.encrypt_aes_gcm(&key, &nonce, plaintext, &[]);
    assert!(encrypt_result.is_ok(), "AES-GCM encryption should work");
    
    let ciphertext = encrypt_result.unwrap();
    assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
}
