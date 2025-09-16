//! Tests for real TLS handshake implementation
//!
//! This module contains tests that expose mock implementations in the TLS handshake
//! and validate that real cryptographic operations are implemented correctly.

use zktls_core::tls::enhanced_state_machine::EnhancedHandshakeStateMachine;
use zktls_core::tls::handshake::{ClientHello, ServerHello};
use zktls_core::tls::state_machine::HandshakeState;
use zktls_crypto::native::NativeCryptoProvider;

/// Test that exposes mock key derivation in handshake state machine
#[test]
fn test_handshake_key_derivation_not_mocked() {
    let crypto_provider = NativeCryptoProvider::new();
    let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider);
    
    // Create a ClientHello message
    let client_hello = ClientHello {
        legacy_version: 0x0303,
        random: [0x01; 32],
        legacy_session_id: Vec::new(),
        cipher_suites: vec![0x1301], // TLS_AES_128_GCM_SHA256
        legacy_compression_methods: vec![0x00],
        extensions: Vec::new(),
    };
    
    let client_hello_msg = client_hello.to_handshake_message().unwrap();
    
    // Process ClientHello
    state_machine.process_outbound_message(&client_hello_msg).unwrap();
    
    // Create a ServerHello message
    let server_hello = ServerHello {
        legacy_version: 0x0303,
        random: [0x02; 32],
        legacy_session_id_echo: Vec::new(),
        cipher_suite: 0x1301,
        legacy_compression_method: 0x00,
        extensions: Vec::new(),
    };
    
    let server_hello_msg = server_hello.to_handshake_message().unwrap();
    
    // Process ServerHello
    state_machine.process_inbound_message(&server_hello_msg).unwrap();
    
    // At this point, the state machine should have derived real handshake secrets
    // Let's check if we can get the handshake traffic secrets
    let handshake_secrets = state_machine.derive_handshake_traffic_keys().unwrap();
    
    // The secrets should not be all zeros or simple patterns (which would indicate mocking)
    let client_secret = handshake_secrets.client_handshake_traffic_secret;
    let server_secret = handshake_secrets.server_handshake_traffic_secret;
    
    // Check that secrets are not all zeros
    assert!(!client_secret.iter().all(|&x| x == 0), 
        "Client handshake secret should not be all zeros (indicates mock implementation)");
    assert!(!server_secret.iter().all(|&x| x == 0), 
        "Server handshake secret should not be all zeros (indicates mock implementation)");
    
    // Check that secrets are different
    assert_ne!(client_secret, server_secret, 
        "Client and server handshake secrets should be different");
    
    // Check that secrets are not simple patterns (like all 0x01, 0x02, etc.)
    assert!(!client_secret.iter().all(|&x| x == 0x01), 
        "Client handshake secret should not be all 0x01 (indicates mock implementation)");
    assert!(!server_secret.iter().all(|&x| x == 0x02), 
        "Server handshake secret should not be all 0x02 (indicates mock implementation)");
}

/// Test that validates real ECDHE shared secret computation
#[test]
fn test_ecdhe_shared_secret_computation() {
    let crypto_provider = NativeCryptoProvider::new();
    let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider);
    
    // Create ClientHello with key_share extension
    let mut client_hello = ClientHello {
        legacy_version: 0x0303,
        random: [0x01; 32],
        legacy_session_id: Vec::new(),
        cipher_suites: vec![0x1301],
        legacy_compression_methods: vec![0x00],
        extensions: Vec::new(),
    };
    
    // Add key_share extension with client public key
    let client_public_key = [0x03; 32]; // Mock public key for testing
    let key_share_extension = create_key_share_extension(client_public_key);
    client_hello.extensions = key_share_extension;
    
    let client_hello_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&client_hello_msg).unwrap();
    
    // Create ServerHello with server key_share
    let mut server_hello = ServerHello {
        legacy_version: 0x0303,
        random: [0x02; 32],
        legacy_session_id_echo: Vec::new(),
        cipher_suite: 0x1301,
        legacy_compression_method: 0x00,
        extensions: Vec::new(),
    };
    
    // Add server key_share extension
    let server_public_key = [0x04; 32]; // Mock server public key
    let server_key_share = create_key_share_extension(server_public_key);
    server_hello.extensions = server_key_share;
    
    let server_hello_msg = server_hello.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&server_hello_msg).unwrap();
    
    // The state machine should have computed a real ECDHE shared secret
    // We can't directly access it, but we can verify that handshake secrets were derived
    let handshake_secrets = state_machine.derive_handshake_traffic_keys().unwrap();
    
    // The secrets should be cryptographically derived, not hardcoded
    assert!(!handshake_secrets.client_handshake_traffic_secret.iter().all(|&x| x == 0x01), 
        "Handshake secrets should be cryptographically derived, not hardcoded");
}

/// Test that validates real transcript hash computation
#[test]
fn test_transcript_hash_computation() {
    let crypto_provider = NativeCryptoProvider::new();
    let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider);
    
    // Create and process multiple handshake messages
    let client_hello = ClientHello {
        legacy_version: 0x0303,
        random: [0x01; 32],
        legacy_session_id: Vec::new(),
        cipher_suites: vec![0x1301],
        legacy_compression_methods: vec![0x00],
        extensions: Vec::new(),
    };
    
    let client_hello_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&client_hello_msg).unwrap();
    
    let server_hello = ServerHello {
        legacy_version: 0x0303,
        random: [0x02; 32],
        legacy_session_id_echo: Vec::new(),
        cipher_suite: 0x1301,
        legacy_compression_method: 0x00,
        extensions: Vec::new(),
    };
    
    let server_hello_msg = server_hello.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&server_hello_msg).unwrap();
    
    // Get the current transcript hash
    let transcript_hash = state_machine.transcript().current_hash();
    
    // The hash should not be all zeros or simple patterns
    assert!(!transcript_hash.iter().all(|&x| x == 0), 
        "Transcript hash should not be all zeros (indicates mock implementation)");
    
    // The hash should be 32 bytes (SHA-256)
    assert_eq!(transcript_hash.len(), 32, 
        "Transcript hash should be 32 bytes (SHA-256)");
    
    // The hash should be deterministic for the same input
    let transcript_hash2 = state_machine.transcript().current_hash();
    assert_eq!(transcript_hash, transcript_hash2, 
        "Transcript hash should be deterministic");
}

/// Helper function to create a key_share extension
fn create_key_share_extension(public_key: [u8; 32]) -> Vec<u8> {
    let mut extension = Vec::new();
    
    // Extension type: key_share (0x0033)
    extension.extend_from_slice(&[0x00, 0x33]);
    
    // Extension length (will be calculated)
    let mut extension_data = Vec::new();
    
    // KeyShareEntry
    extension_data.extend_from_slice(&[0x00, 0x1d]); // group: X25519
    extension_data.extend_from_slice(&[0x00, 0x20]); // key_exchange length: 32
    extension_data.extend_from_slice(&public_key);
    
    // Extension data length
    let data_len = extension_data.len() as u16;
    extension.extend_from_slice(&data_len.to_be_bytes());
    extension.extend_from_slice(&extension_data);
    
    extension
}
