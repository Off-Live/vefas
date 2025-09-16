//! Integration tests for TLS 1.3 handshake state machine
//! 
//! These tests define the expected behavior of the complete TLS 1.3 handshake
//! state machine according to RFC 8446. Following strict TDD methodology,
//! these tests will initially fail and drive the implementation.

use zktls_core::{
    tls::{
        state_machine::{HandshakeStateMachine, HandshakeState, StateTransition},
        transcript::TranscriptHash,
        handshake::{HandshakeMessage, HandshakeType, ClientHello, ServerHello, Certificate, Finished},
        messages::TlsRecord,
    },
    errors::{ZkTlsError, ZkTlsResult, ProtocolError},
};
use hex_literal::hex;

#[test] 
fn test_handshake_state_machine_initialization() {
    // RED: This test will fail until we implement HandshakeStateMachine
    let mut state_machine = HandshakeStateMachine::new();
    
    // State machine should start in IDLE state
    assert_eq!(state_machine.current_state(), HandshakeState::Idle);
    
    // Should have empty transcript initially
    assert_eq!(state_machine.transcript().current_hash().len(), 32); // SHA-256
    assert_eq!(state_machine.transcript().message_count(), 0);
}

#[test]
fn test_client_hello_state_transition() {
    // RED: Test the complete CLIENT_HELLO state transition
    let mut state_machine = HandshakeStateMachine::new();
    
    // Create a mock ClientHello message
    let client_hello = ClientHello {
        legacy_version: 0x0303,
        random: [0u8; 32], // Mock random
        legacy_session_id: vec![],
        cipher_suites: vec![0x1301], // TLS_AES_128_GCM_SHA256
        legacy_compression_methods: vec![0x00],
        extensions: vec![], // Mock extensions
    };
    
    let handshake_msg = client_hello.to_handshake_message().unwrap();
    
    // Transition from IDLE -> WAIT_SH by sending ClientHello
    let result = state_machine.process_outbound_message(&handshake_msg);
    assert!(result.is_ok());
    
    // Should now be in WAIT_SH state waiting for ServerHello
    assert_eq!(state_machine.current_state(), HandshakeState::WaitServerHello);
    
    // Transcript should contain ClientHello
    assert_eq!(state_machine.transcript().message_count(), 1);
}

#[test]
fn test_server_hello_state_transition() {
    // RED: Test ServerHello processing and state transition  
    let mut state_machine = HandshakeStateMachine::new();
    
    // First, send ClientHello to reach WAIT_SH state
    let client_hello = create_mock_client_hello();
    let ch_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&ch_msg).unwrap();
    
    // Create mock ServerHello
    let server_hello = ServerHello {
        legacy_version: 0x0303,
        random: [1u8; 32], // Different from client
        legacy_session_id_echo: vec![],
        cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
        legacy_compression_method: 0x00,
        extensions: vec![], // Mock extensions with supported_versions
    };
    
    let sh_msg = server_hello.to_handshake_message().unwrap();
    
    // Process ServerHello - should transition to WAIT_EE
    let result = state_machine.process_inbound_message(&sh_msg);
    assert!(result.is_ok());
    
    assert_eq!(state_machine.current_state(), HandshakeState::WaitEncryptedExtensions);
    assert_eq!(state_machine.transcript().message_count(), 2);
}

#[test] 
fn test_complete_tls13_handshake_flow() {
    // RED: Test the complete TLS 1.3 handshake state machine flow
    // This is the most comprehensive test that drives implementation
    let mut state_machine = HandshakeStateMachine::new();
    
    // Step 1: Client sends ClientHello (IDLE -> WAIT_SH)
    let client_hello = create_mock_client_hello();
    let ch_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&ch_msg).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitServerHello);
    
    // Step 2: Receive ServerHello (WAIT_SH -> WAIT_EE)
    let server_hello = create_mock_server_hello();
    let sh_msg = server_hello.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&sh_msg).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitEncryptedExtensions);
    
    // Step 3: Receive EncryptedExtensions (WAIT_EE -> WAIT_CERT_CR)
    let encrypted_exts = create_mock_encrypted_extensions();
    state_machine.process_inbound_message(&encrypted_exts).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitCertificateOrCertificateRequest);
    
    // Step 4: Receive Certificate (WAIT_CERT_CR -> WAIT_CV)
    let certificate = create_mock_certificate();
    let cert_msg = certificate.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&cert_msg).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitCertificateVerify);
    
    // Step 5: Receive CertificateVerify (WAIT_CV -> WAIT_FINISHED)
    let cert_verify = create_mock_certificate_verify();
    state_machine.process_inbound_message(&cert_verify).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitServerFinished);
    
    // Step 6: Receive Server Finished (WAIT_FINISHED -> WAIT_FLIGHT2)
    let server_finished = create_mock_server_finished();
    let sf_msg = server_finished.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&sf_msg).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::WaitFlight2);
    
    // Step 7: Send Client Finished (WAIT_FLIGHT2 -> CONNECTED)
    let client_finished = create_mock_client_finished();
    let cf_msg = client_finished.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&cf_msg).unwrap();
    assert_eq!(state_machine.current_state(), HandshakeState::Connected);
    
    // Verify transcript contains all messages
    assert_eq!(state_machine.transcript().message_count(), 7);
    
    // Should be able to derive application traffic keys
    let keys = state_machine.derive_application_traffic_keys();
    assert!(keys.is_ok());
    
    let session_keys = keys.unwrap();
    assert_eq!(session_keys.client_traffic_key.len(), 32);
    assert_eq!(session_keys.server_traffic_key.len(), 32);
    assert_eq!(session_keys.client_traffic_iv.len(), 12);
    assert_eq!(session_keys.server_traffic_iv.len(), 12);
}

#[test]
fn test_invalid_state_transitions() {
    // RED: Test that invalid state transitions are properly rejected
    let mut state_machine = HandshakeStateMachine::new();
    
    // Cannot process ServerHello in IDLE state (should be in WAIT_SH)
    let server_hello = create_mock_server_hello();
    let sh_msg = server_hello.to_handshake_message().unwrap();
    let result = state_machine.process_inbound_message(&sh_msg);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ZkTlsError::ProtocolError(ProtocolError::InvalidStateTransition(_))));
    
    // Cannot send ClientHello twice
    let client_hello = create_mock_client_hello();
    let ch_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&ch_msg).unwrap(); // First one OK
    
    let result = state_machine.process_outbound_message(&ch_msg); // Second should fail
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), ZkTlsError::ProtocolError(ProtocolError::InvalidStateTransition(_))));
}

#[test]
fn test_transcript_hash_progression() {
    // RED: Test that transcript hashes are properly maintained throughout handshake
    let mut state_machine = HandshakeStateMachine::new();
    
    // Initial transcript should be empty SHA-256
    let empty_hash = state_machine.transcript().current_hash();
    assert_eq!(empty_hash.len(), 32);
    
    // Add ClientHello
    let client_hello = create_mock_client_hello();
    let ch_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&ch_msg).unwrap();
    
    let hash_after_ch = state_machine.transcript().current_hash();
    assert_ne!(hash_after_ch, empty_hash); // Should have changed
    
    // Add ServerHello  
    let server_hello = create_mock_server_hello();
    let sh_msg = server_hello.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&sh_msg).unwrap();
    
    let hash_after_sh = state_machine.transcript().current_hash();
    assert_ne!(hash_after_sh, hash_after_ch); // Should have changed again
    
    // Verify we can get intermediate transcript hashes
    let client_hello_hash = state_machine.transcript().hash_at_message(1);
    assert!(client_hello_hash.is_ok());
    assert_eq!(client_hello_hash.unwrap(), hash_after_ch);
}

#[test]
fn test_key_schedule_progression() {
    // RED: Test TLS 1.3 key schedule progression through handshake states
    let mut state_machine = HandshakeStateMachine::new();
    
    // Process handshake up to ServerHello
    process_handshake_to_server_hello(&mut state_machine);
    
    // At this point we should be able to derive handshake traffic keys
    let handshake_keys = state_machine.derive_handshake_traffic_keys();
    assert!(handshake_keys.is_ok());
    
    let hs_keys = handshake_keys.unwrap();
    assert_eq!(hs_keys.client_handshake_traffic_secret.len(), 32);
    assert_eq!(hs_keys.server_handshake_traffic_secret.len(), 32);
    
    // Complete handshake to derive application keys
    process_remaining_handshake(&mut state_machine);
    
    let app_keys = state_machine.derive_application_traffic_keys();
    assert!(app_keys.is_ok());
    
    let app_keys = app_keys.unwrap();
    assert_eq!(app_keys.client_traffic_key.len(), 32);
    assert_eq!(app_keys.server_traffic_key.len(), 32);
}

#[test]
fn test_resumption_state_handling() {
    // RED: Test 0-RTT/PSK resumption state handling (limited scope for MVP)
    let mut state_machine = HandshakeStateMachine::new();
    
    // For MVP, we should reject PSK/0-RTT attempts gracefully
    let client_hello_with_psk = create_client_hello_with_psk();
    let ch_msg = client_hello_with_psk.to_handshake_message().unwrap();
    
    // Should accept ClientHello but not enable 0-RTT mode  
    let result = state_machine.process_outbound_message(&ch_msg);
    assert!(result.is_ok());
    assert_eq!(state_machine.current_state(), HandshakeState::WaitServerHello);
    assert!(!state_machine.is_early_data_enabled());
}

// Helper functions for creating mock handshake messages

fn create_mock_client_hello() -> ClientHello {
    ClientHello {
        legacy_version: 0x0303,
        random: hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
        legacy_session_id: vec![],
        cipher_suites: vec![0x1301, 0x1302, 0x1303], // AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305
        legacy_compression_methods: vec![0x00],
        extensions: create_mock_client_extensions(),
    }
}

fn create_mock_server_hello() -> ServerHello {
    ServerHello {
        legacy_version: 0x0303,
        random: hex!("ffeeddccbbaa998877665544332211000123456789abcdef0123456789abcdef"),
        legacy_session_id_echo: vec![],
        cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
        legacy_compression_method: 0x00,
        extensions: create_mock_server_extensions(),
    }
}

fn create_mock_certificate() -> Certificate {
    Certificate {
        certificate_request_context: vec![],
        certificate_list: vec![0x01, 0x02, 0x03], // Mock certificate data
    }
}

fn create_mock_server_finished() -> Finished {
    Finished {
        verify_data: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                         0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                         0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                         0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20],
    }
}

fn create_mock_client_finished() -> Finished {
    Finished {
        verify_data: vec![0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
                         0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
                         0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
                         0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
    }
}

fn create_mock_encrypted_extensions() -> HandshakeMessage {
    // Mock EncryptedExtensions message
    HandshakeMessage::new(
        HandshakeType::EncryptedExtensions,
        vec![0x00, 0x00] // Empty extensions for now
    ).unwrap()
}

fn create_mock_certificate_verify() -> HandshakeMessage {
    // Mock CertificateVerify message
    HandshakeMessage::new(
        HandshakeType::CertificateVerify,
        vec![0x08, 0x04, // RSA-PSS-RSAE-SHA256
             0x00, 0x40, // 64 bytes signature
             // Mock signature bytes
             0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
             0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
             0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
             0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
             0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
             0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
             0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40]
    ).unwrap()
}

fn create_mock_client_extensions() -> Vec<u8> {
    // Mock client extensions including supported_versions, key_share, etc.
    vec![
        // supported_versions extension
        0x00, 0x2b, // extension_type = supported_versions
        0x00, 0x03, // length = 3
        0x02,       // versions length = 2  
        0x03, 0x04, // TLS 1.3
        
        // key_share extension  
        0x00, 0x33, // extension_type = key_share
        0x00, 0x24, // length = 36
        0x00, 0x22, // key_share length = 34
        0x00, 0x1d, // group = x25519
        0x00, 0x20, // key_exchange length = 32
        // 32 bytes of mock X25519 public key
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ]
}

fn create_mock_server_extensions() -> Vec<u8> {
    // Mock server extensions including supported_versions, key_share
    vec![
        // supported_versions extension
        0x00, 0x2b, // extension_type = supported_versions
        0x00, 0x02, // length = 2
        0x03, 0x04, // TLS 1.3
        
        // key_share extension
        0x00, 0x33, // extension_type = key_share
        0x00, 0x24, // length = 36
        0x00, 0x1d, // group = x25519
        0x00, 0x20, // key_exchange length = 32
        // 32 bytes of mock X25519 public key
        0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
        0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
        0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ]
}

fn create_client_hello_with_psk() -> ClientHello {
    let mut client_hello = create_mock_client_hello();
    // Add PSK extension to test resumption handling
    client_hello.extensions.extend_from_slice(&[
        0x00, 0x29, // extension_type = pre_shared_key
        0x00, 0x08, // length = 8
        0x00, 0x04, // identities length = 4
        0x00, 0x02, // identity length = 2
        0x01, 0x02, // mock PSK identity
        0x00, 0x00, // obfuscated_ticket_age = 0
        0x01,       // binders length = 1
        0x00,       // empty binder
    ]);
    client_hello
}

fn process_handshake_to_server_hello(state_machine: &mut HandshakeStateMachine) {
    // Helper to process handshake up to ServerHello
    let client_hello = create_mock_client_hello();
    let ch_msg = client_hello.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&ch_msg).unwrap();
    
    let server_hello = create_mock_server_hello();
    let sh_msg = server_hello.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&sh_msg).unwrap();
}

fn process_remaining_handshake(state_machine: &mut HandshakeStateMachine) {
    // Helper to complete handshake from current state to CONNECTED
    let encrypted_exts = create_mock_encrypted_extensions();
    state_machine.process_inbound_message(&encrypted_exts).unwrap();
    
    let certificate = create_mock_certificate();
    let cert_msg = certificate.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&cert_msg).unwrap();
    
    let cert_verify = create_mock_certificate_verify();
    state_machine.process_inbound_message(&cert_verify).unwrap();
    
    let server_finished = create_mock_server_finished();
    let sf_msg = server_finished.to_handshake_message().unwrap();
    state_machine.process_inbound_message(&sf_msg).unwrap();
    
    let client_finished = create_mock_client_finished();
    let cf_msg = client_finished.to_handshake_message().unwrap();
    state_machine.process_outbound_message(&cf_msg).unwrap();
}