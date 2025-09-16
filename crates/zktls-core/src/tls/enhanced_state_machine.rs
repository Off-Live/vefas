//! Enhanced TLS 1.3 Handshake State Machine with Real Cryptography
//!
//! This module provides an enhanced handshake state machine that uses real
//! cryptographic operations through the zktls-crypto provider. It extracts
//! key shares from extensions, computes real ECDHE shared secrets, and uses
//! the TLS 1.3 key schedule for deriving traffic keys.

use crate::{
    errors::{ZkTlsError, ZkTlsResult},
    tls::{
        handshake::{HandshakeMessage, HandshakeType, ClientHello, ServerHello, CertificateVerify, SignatureScheme},
        transcript::TranscriptHash,
        key_schedule::{Tls13KeySchedule, HandshakeTrafficSecrets, ApplicationTrafficSecrets},
        state_machine::{HandshakeState, StateTransition},
    },
    x509::certificate::X509Certificate,
};
use zktls_crypto::{CryptoProvider, Hash, Kdf, KeyExchange};
use alloc::{vec::Vec, format};

/// Enhanced TLS 1.3 Client Handshake State Machine with Real Cryptography
/// 
/// This state machine uses real cryptographic operations to:
/// - Extract key_share extensions from handshake messages
/// - Compute ECDHE shared secrets using X25519
/// - Derive traffic keys using RFC 8446 key schedule
/// - Validate handshake integrity with real transcript hashes
#[derive(Debug)]
pub struct EnhancedHandshakeStateMachine<P>
where
    P: CryptoProvider + Hash + Kdf + KeyExchange
{
    /// Current handshake state
    current_state: HandshakeState,
    /// Transcript hash of all handshake messages
    transcript: TranscriptHash,
    /// Whether early data (0-RTT) is enabled
    early_data_enabled: bool,
    /// Client ECDHE private key (stored for shared secret computation)
    client_private_key: Option<Vec<u8>>,
    /// Client and server random values
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    /// Selected cipher suite
    cipher_suite: Option<u16>,
    /// Server certificate raw data for signature verification
    server_certificate_data: Option<Vec<u8>>,
    /// Real TLS 1.3 key schedule for key derivation
    key_schedule: Tls13KeySchedule<P>,
    /// Cryptographic provider for ECDHE and other operations
    crypto_provider: P,
}

impl<P> EnhancedHandshakeStateMachine<P>
where
    P: CryptoProvider + Hash + Kdf + KeyExchange + Clone
{
    /// Create a new enhanced handshake state machine with real cryptography
    pub fn new(crypto_provider: P) -> Self {
        let key_schedule = Tls13KeySchedule::new(crypto_provider.clone());
        
        Self {
            current_state: HandshakeState::Idle,
            transcript: TranscriptHash::new(),
            early_data_enabled: false,
            client_private_key: None,
            client_random: None,
            server_random: None,
            cipher_suite: None,
            server_certificate_data: None,
            key_schedule,
            crypto_provider,
        }
    }
    
    
    /// Get the current handshake state
    pub fn current_state(&self) -> HandshakeState {
        self.current_state
    }
    
    /// Get a reference to the transcript hash
    pub fn transcript(&self) -> &TranscriptHash {
        &self.transcript
    }
    
    /// Check if early data (0-RTT) is enabled
    pub fn is_early_data_enabled(&self) -> bool {
        self.early_data_enabled
    }
    
    /// Process an outbound handshake message (sent by client)
    /// 
    /// This method validates the message against the current state,
    /// updates the transcript, and transitions to the next state.
    pub fn process_outbound_message(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        match (self.current_state, message.msg_type) {
            (HandshakeState::Idle, HandshakeType::ClientHello) => {
                self.process_client_hello_send(message)?;
                self.transition_to(HandshakeState::WaitServerHello, StateTransition::SendClientHello)
            },
            (HandshakeState::WaitFlight2, HandshakeType::Finished) => {
                self.process_client_finished_send(message)?;
                self.transition_to(HandshakeState::Connected, StateTransition::SendClientFinished)
            },
            _ => {
                return Err(ZkTlsError::invalid_state_transition(
                    format!("Cannot send {:?} in state {:?}", 
                            message.msg_type, self.current_state)
                ));
            }
        }
    }
    
    /// Process an inbound handshake message (received from server)
    /// 
    /// This method validates the message against the current state,
    /// updates the transcript, performs cryptographic operations,
    /// and transitions to the next state.
    pub fn process_inbound_message(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        match (self.current_state, message.msg_type) {
            (HandshakeState::WaitServerHello, HandshakeType::ServerHello) => {
                self.process_server_hello_receive(message)?;
                self.transition_to(HandshakeState::WaitEncryptedExtensions, StateTransition::ReceiveServerHello)
            },
            (HandshakeState::WaitEncryptedExtensions, HandshakeType::EncryptedExtensions) => {
                self.process_encrypted_extensions_receive(message)?;
                self.transition_to(HandshakeState::WaitCertificateOrCertificateRequest, StateTransition::ReceiveEncryptedExtensions)
            },
            (HandshakeState::WaitCertificateOrCertificateRequest, HandshakeType::Certificate) => {
                self.process_certificate_receive(message)?;
                self.transition_to(HandshakeState::WaitCertificateVerify, StateTransition::ReceiveCertificate)
            },
            (HandshakeState::WaitCertificateVerify, HandshakeType::CertificateVerify) => {
                self.process_certificate_verify_receive(message)?;
                self.transition_to(HandshakeState::WaitServerFinished, StateTransition::ReceiveCertificateVerify)
            },
            (HandshakeState::WaitServerFinished, HandshakeType::Finished) => {
                self.process_server_finished_receive(message)?;
                self.transition_to(HandshakeState::WaitFlight2, StateTransition::ReceiveServerFinished)
            },
            _ => {
                return Err(ZkTlsError::invalid_state_transition(
                    format!("Cannot receive {:?} in state {:?}", 
                            message.msg_type, self.current_state)
                ));
            }
        }
    }
    
    /// Derive handshake traffic keys using real key schedule
    pub fn derive_handshake_traffic_keys(&self) -> ZkTlsResult<HandshakeTrafficSecrets> {
        if self.current_state < HandshakeState::WaitEncryptedExtensions {
            return Err(ZkTlsError::invalid_state_transition(
                "Handshake traffic keys not available - ServerHello not processed"
            ));
        }
        
        // Get current transcript hash for key derivation
        let transcript_hash = self.transcript.current_hash();
        self.key_schedule.derive_handshake_traffic_secrets(&transcript_hash)
    }
    
    /// Derive application traffic keys using real key schedule
    pub fn derive_application_traffic_keys(&self) -> ZkTlsResult<ApplicationTrafficSecrets> {
        if self.current_state != HandshakeState::Connected {
            return Err(ZkTlsError::invalid_state_transition(
                format!("Application traffic keys not available in state {:?}", self.current_state)
            ));
        }
        
        // Get final transcript hash for application key derivation
        let transcript_hash = self.transcript.current_hash();
        self.key_schedule.derive_application_traffic_secrets(&transcript_hash)
    }
    
    /// Check if the handshake is complete
    pub fn is_handshake_complete(&self) -> bool {
        self.current_state == HandshakeState::Connected
    }
    
    /// Get a reference to the key schedule
    pub fn key_schedule(&self) -> &Tls13KeySchedule<P> {
        &self.key_schedule
    }
    
    /// Validate Server Finished message HMAC using TLS 1.3 key schedule
    /// 
    /// According to RFC 8446 Section 4.4.4:
    /// verify_data = HMAC(finished_key, transcript_hash)
    /// finished_key = HKDF-Expand-Label(server_handshake_traffic_secret, "finished", "", Hash.length)
    fn validate_server_finished_hmac(&self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Parse the Finished message to get verify_data
        let finished = super::handshake::Finished::parse(&message.payload)?;
        
        // Derive handshake traffic secrets
        let transcript_hash = self.transcript.current_hash();
        let traffic_secrets = self.key_schedule.derive_handshake_traffic_secrets(&transcript_hash)?;
        
        // Derive the finished_key from server_handshake_traffic_secret
        let finished_key = self.key_schedule.derive_finished_key(&traffic_secrets.server_handshake_traffic_secret)?;
        
        // Compute expected HMAC over transcript hash (up to but not including this Finished message)
        // Use HKDF extract with the finished_key as salt and transcript_hash as IKM
        // This is effectively HMAC(finished_key, transcript_hash)
        let expected_verify_data = self.crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash)
            .map_err(|_| ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage))?;
        
        
        // Verify the HMAC matches
        if finished.verify_data != expected_verify_data {
            return Err(ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage));
        }
        
        Ok(())
    }
    
    /// Validate Client Finished message HMAC using TLS 1.3 key schedule
    /// 
    /// This ensures that the outgoing Client Finished message contains the correct HMAC.
    /// According to RFC 8446 Section 4.4.4:
    /// verify_data = HMAC(finished_key, transcript_hash)
    /// finished_key = HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", Hash.length)
    fn validate_client_finished_hmac(&self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Parse the Finished message to get verify_data
        let finished = super::handshake::Finished::parse(&message.payload)?;
        
        // Derive handshake traffic secrets
        let transcript_hash = self.transcript.current_hash();
        let traffic_secrets = self.key_schedule.derive_handshake_traffic_secrets(&transcript_hash)?;
        
        // Derive the finished_key from client_handshake_traffic_secret
        let finished_key = self.key_schedule.derive_finished_key(&traffic_secrets.client_handshake_traffic_secret)?;
        
        // Compute expected HMAC over transcript hash (up to but not including this Finished message)
        let expected_verify_data = self.crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash)
            .map_err(|_| ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage))?;
        
        // Verify the HMAC matches
        if finished.verify_data != expected_verify_data {
            return Err(ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage));
        }
        
        Ok(())
    }
    
    /// Get the selected cipher suite (available after ServerHello)
    pub fn selected_cipher_suite(&self) -> Option<u16> {
        self.cipher_suite
    }
    
    /// Generate a Client Finished message with proper HMAC using TLS 1.3 key schedule
    /// 
    /// According to RFC 8446 Section 4.4.4:
    /// verify_data = HMAC(finished_key, transcript_hash)
    /// finished_key = HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", Hash.length)
    pub fn generate_client_finished(&self) -> ZkTlsResult<super::handshake::Finished> {
        if self.current_state != HandshakeState::WaitFlight2 {
            return Err(ZkTlsError::invalid_state_transition(
                format!("Cannot generate client Finished in state {:?}", self.current_state)
            ));
        }
        
        // Derive handshake traffic secrets
        let transcript_hash = self.transcript.current_hash();
        let traffic_secrets = self.key_schedule.derive_handshake_traffic_secrets(&transcript_hash)?;
        
        // Derive the finished_key from client_handshake_traffic_secret
        let finished_key = self.key_schedule.derive_finished_key(&traffic_secrets.client_handshake_traffic_secret)?;
        
        // Compute HMAC over transcript hash (up to this point, not including client Finished)
        let verify_data = self.crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash)
            .map_err(|_| ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage))?;
        
        Ok(super::handshake::Finished {
            verify_data,
        })
    }
    
    // Private helper methods for processing specific messages
    
    fn process_client_hello_send(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Parse ClientHello to extract client random and key share
        let client_hello = ClientHello::parse(&message.payload)?;
        self.client_random = Some(client_hello.random);
        
        // Extract and store client private key from key_share extension
        // In a real implementation, we would generate this key and include it in ClientHello
        // For now, we'll generate it here and store for later use
        let (client_private_key, _client_public_key) = self.crypto_provider.x25519_generate_keypair()
            .map_err(|_| ZkTlsError::invalid_state_transition("Failed to generate client keypair"))?;
        self.client_private_key = Some(client_private_key);
        
        // Add to transcript
        self.transcript.add_message(message)?;
        
        // Initialize key schedule
        self.key_schedule.derive_early_secret(None)
            .map_err(|_| ZkTlsError::invalid_state_transition("Failed to derive early secret"))?;
        
        Ok(())
    }
    
    fn process_server_hello_receive(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Parse ServerHello
        let server_hello = ServerHello::parse(&message.payload)?;
        
        // Validate TLS version (should be 0x0303 with supported_versions extension)
        if server_hello.legacy_version != 0x0303 {
            return Err(ZkTlsError::invalid_state_transition(
                "ServerHello must use legacy version 0x0303 for TLS 1.3"
            ));
        }
        
        // Extract server random and cipher suite
        self.server_random = Some(server_hello.random);
        self.cipher_suite = Some(server_hello.cipher_suite);
        
        // Validate cipher suite is one we support
        match server_hello.cipher_suite {
            0x1301 | 0x1302 | 0x1303 => {}, // TLS_AES_128_GCM, TLS_AES_256_GCM, TLS_CHACHA20_POLY1305
            _ => {
                return Err(ZkTlsError::invalid_state_transition(
                    format!("Unsupported cipher suite: 0x{:04x}", server_hello.cipher_suite)
                ));
            }
        }
        
        // Add to transcript
        self.transcript.add_message(message)?;
        
        // Extract key_share from extensions and compute shared secret
        let shared_secret = self.extract_key_share_and_compute_shared_secret(&server_hello.extensions)?;
        
        // Derive handshake secret
        self.key_schedule.derive_handshake_secret(&shared_secret)
            .map_err(|_| ZkTlsError::invalid_state_transition("Failed to derive handshake secret"))?;
        
        Ok(())
    }
    
    fn extract_key_share_and_compute_shared_secret(&self, extensions_data: &[u8]) -> ZkTlsResult<Vec<u8>> {
        // Parse extensions to find KeyShare
        let mut cursor = 0;
        
        while cursor < extensions_data.len() {
            if cursor + 4 > extensions_data.len() {
                break;
            }
            
            // Parse extension type (2 bytes)
            let ext_type = u16::from_be_bytes([
                extensions_data[cursor],
                extensions_data[cursor + 1]
            ]);
            cursor += 2;
            
            // Parse extension length (2 bytes)
            let ext_length = u16::from_be_bytes([
                extensions_data[cursor],
                extensions_data[cursor + 1]
            ]) as usize;
            cursor += 2;
            
            if cursor + ext_length > extensions_data.len() {
                return Err(ZkTlsError::invalid_state_transition("Invalid extension length"));
            }
            
            // Check if this is a KeyShare extension
            if ext_type == 51 { // KeyShare extension type
                let key_share_data = &extensions_data[cursor..cursor + ext_length];
                return self.process_key_share_extension(key_share_data);
            }
            
            cursor += ext_length;
        }
        
        Err(ZkTlsError::invalid_state_transition("No KeyShare extension found in ServerHello"))
    }
    
    fn process_key_share_extension(&self, key_share_data: &[u8]) -> ZkTlsResult<Vec<u8>> {
        // Parse KeyShare extension data
        // For ServerHello, this is just a single KeyShareEntry
        if key_share_data.len() < 4 {
            return Err(ZkTlsError::invalid_state_transition("KeyShare extension too short"));
        }
        
        let mut cursor = 0;
        
        // Parse group (2 bytes)
        let group = u16::from_be_bytes([key_share_data[cursor], key_share_data[cursor + 1]]);
        cursor += 2;
        
        // Parse key exchange length (2 bytes)
        let key_length = u16::from_be_bytes([key_share_data[cursor], key_share_data[cursor + 1]]) as usize;
        cursor += 2;
        
        if cursor + key_length > key_share_data.len() {
            return Err(ZkTlsError::invalid_state_transition("Invalid key exchange length"));
        }
        
        // Extract server public key
        let server_public_key = &key_share_data[cursor..cursor + key_length];
        
        // Verify this is X25519 group (29)
        if group != 29 {
            return Err(ZkTlsError::invalid_state_transition(
                format!("Unsupported key share group: {}", group)
            ));
        }
        
        if server_public_key.len() != 32 {
            return Err(ZkTlsError::invalid_state_transition("Invalid X25519 public key length"));
        }
        
        // Compute shared secret using client private key
        if let Some(client_private_key) = &self.client_private_key {
            self.crypto_provider.x25519_diffie_hellman(client_private_key, server_public_key)
                .map_err(|_| ZkTlsError::invalid_state_transition("Failed to compute ECDHE shared secret"))
        } else {
            Err(ZkTlsError::invalid_state_transition("Client private key not available"))
        }
    }
    
    fn process_encrypted_extensions_receive(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Add to transcript
        self.transcript.add_message(message)?;
        
        // TODO: Parse EncryptedExtensions for any server configuration
        // For MVP, we just validate the message format
        
        Ok(())
    }
    
    fn process_certificate_receive(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Add to transcript
        self.transcript.add_message(message)?;
        
        // Parse Certificate message to extract server certificate
        let certificate = super::handshake::Certificate::parse(&message.payload)?;
        
        // Extract the first (end-entity) certificate from the chain
        // Certificate list format: 3-byte length + certificate entries
        // Each entry: 3-byte cert length + cert data + 2-byte extensions length + extensions
        if certificate.certificate_list.len() < 3 {
            return Err(ZkTlsError::invalid_state_transition("Empty certificate list"));
        }
        
        let mut cursor = 0;
        let cert_data_length = u32::from_be_bytes([
            0,
            certificate.certificate_list[cursor],
            certificate.certificate_list[cursor + 1],
            certificate.certificate_list[cursor + 2]
        ]) as usize;
        cursor += 3;
        
        if cursor + cert_data_length > certificate.certificate_list.len() {
            return Err(ZkTlsError::invalid_state_transition("Invalid certificate data length"));
        }
        
        let cert_data = &certificate.certificate_list[cursor..cursor + cert_data_length];
        
        // Store the server certificate raw data for signature verification
        self.server_certificate_data = Some(cert_data.to_vec());
        
        Ok(())
    }
    
    fn process_certificate_verify_receive(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // IMPORTANT: Verify the signature BEFORE adding to transcript
        // The signature is computed over the transcript hash up to (but not including) this message
        self.validate_certificate_verify_signature(message)?;
        
        // Add to transcript after validation
        self.transcript.add_message(message)?;
        
        Ok(())
    }
    
    /// Validate CertificateVerify signature per RFC 8446 Section 4.4.3
    /// 
    /// The signature is computed over:
    /// " " * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    fn validate_certificate_verify_signature(&self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Parse the CertificateVerify message
        let cert_verify = CertificateVerify::parse(&message.payload)?;
        
        // In test mode, skip signature verification
        
        // Get the server certificate data for public key extraction
        let server_cert_data = self.server_certificate_data.as_ref()
            .ok_or_else(|| ZkTlsError::invalid_state_transition("No server certificate available"))?;
        
        // Production code: Always validate certificates - no bypasses allowed
        // All certificates must be properly validated regardless of size or format
        
        // Parse the X.509 certificate
        let server_cert = X509Certificate::parse(server_cert_data)
            .map_err(|_| ZkTlsError::invalid_state_transition("Failed to parse server certificate"))?;
        
        // Construct the signature context per RFC 8446 Section 4.4.3
        let mut signature_context = Vec::new();
        signature_context.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        signature_context.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signature_context.push(0x00); // separator byte
        
        // Get transcript hash up to this point (not including this CertificateVerify message)
        let transcript_hash = self.transcript.current_hash();
        signature_context.extend_from_slice(&transcript_hash);
        
        // Extract public key from server certificate
        let public_key_info = server_cert.public_key();
        
        // Verify signature based on algorithm
        match cert_verify.algorithm {
            SignatureScheme::EcdsaSecp256r1Sha256 => {
                // For ECDSA, we need to hash the signature context with SHA-256
                let message_hash = self.crypto_provider.sha256(&signature_context);
                
                // Extract ECDSA public key from certificate
                let public_key_bytes = public_key_info.extract_ecdsa_public_key()
                    .map_err(|_| ZkTlsError::invalid_state_transition("Failed to extract ECDSA public key"))?;
                
                // Verify signature using prehashed verification
                let is_valid = self.crypto_provider.p256_verify_prehashed(
                    &public_key_bytes,
                    &message_hash,
                    &cert_verify.signature
                ).map_err(|_| ZkTlsError::invalid_state_transition("Signature verification failed"))?;
                
                if !is_valid {
                    return Err(ZkTlsError::invalid_state_transition("CertificateVerify signature validation failed"));
                }
            }
            SignatureScheme::RsaPkcs1Sha256 | 
            SignatureScheme::RsaPssRsaeSha256 => {
                // For RSA, verify using the RSA verification method
                let public_key_der = public_key_info.extract_rsa_public_key()
                    .map_err(|_| ZkTlsError::invalid_state_transition("Failed to extract RSA public key"))?;
                
                let is_valid = self.crypto_provider.rsa_verify(
                    &public_key_der,
                    &signature_context,
                    &cert_verify.signature,
                    "sha256"
                ).map_err(|_| ZkTlsError::invalid_state_transition("RSA signature verification failed"))?;
                
                if !is_valid {
                    return Err(ZkTlsError::invalid_state_transition("CertificateVerify RSA signature validation failed"));
                }
            }
            SignatureScheme::Ed25519 => {
                // For Ed25519, verify directly (Ed25519 includes its own hashing)
                let public_key_bytes = public_key_info.extract_ed25519_public_key()
                    .map_err(|_| ZkTlsError::invalid_state_transition("Failed to extract Ed25519 public key"))?;
                
                let is_valid = self.crypto_provider.ed25519_verify(
                    &public_key_bytes,
                    &signature_context,
                    &cert_verify.signature
                ).map_err(|_| ZkTlsError::invalid_state_transition("Ed25519 signature verification failed"))?;
                
                if !is_valid {
                    return Err(ZkTlsError::invalid_state_transition("CertificateVerify Ed25519 signature validation failed"));
                }
            }
            _ => {
                return Err(ZkTlsError::invalid_state_transition(
                    format!("Unsupported signature scheme: {:?}", cert_verify.algorithm)
                ));
            }
        }
        
        Ok(())
    }
    
    fn process_server_finished_receive(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // IMPORTANT: Verify the Finished message HMAC BEFORE adding to transcript
        // The transcript hash used for verification should NOT include this Finished message
        self.validate_server_finished_hmac(message)?;
        
        // Add to transcript after validation
        self.transcript.add_message(message)?;
        
        Ok(())
    }
    
    fn process_client_finished_send(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // IMPORTANT: Validate the Client Finished message BEFORE adding to transcript
        // This ensures we're sending the correct HMAC
        self.validate_client_finished_hmac(message)?;
        
        // Add to transcript after validation
        self.transcript.add_message(message)?;
        
        // Derive master secret now that handshake is complete
        self.key_schedule.derive_master_secret()
            .map_err(|_| ZkTlsError::invalid_state_transition("Failed to derive master secret"))?;
        
        Ok(())
    }
    
    fn transition_to(&mut self, new_state: HandshakeState, _transition: StateTransition) -> ZkTlsResult<()> {
        self.current_state = new_state;
        Ok(())
    }
}

impl<P> Default for EnhancedHandshakeStateMachine<P>
where
    P: CryptoProvider + Hash + Kdf + KeyExchange + Clone + Default
{
    fn default() -> Self {
        Self::new(P::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zktls_crypto::native::NativeCryptoProvider;
    use crate::tls::handshake::{Certificate, Finished, CertificateVerify, SignatureScheme};
    use hex_literal::hex;
    use alloc::vec;
    
    #[test]
    fn test_enhanced_state_machine_initialization() {
        let crypto_provider = NativeCryptoProvider::new();
        let state_machine = EnhancedHandshakeStateMachine::new(crypto_provider);
        
        assert_eq!(state_machine.current_state(), HandshakeState::Idle);
        assert_eq!(state_machine.transcript().message_count(), 0);
        assert!(!state_machine.is_early_data_enabled());
        assert!(!state_machine.is_handshake_complete());
        assert!(state_machine.selected_cipher_suite().is_none());
    }
    
    #[test]
    fn test_enhanced_client_hello_transition() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider);
        
        // Create mock ClientHello
        let client_hello = ClientHello {
            legacy_version: 0x0303,
            random: hex!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301],
            legacy_compression_methods: vec![0x00],
            extensions: vec![],
        };
        
        let ch_msg = client_hello.to_handshake_message().unwrap();
        
        // Process ClientHello
        assert!(state_machine.process_outbound_message(&ch_msg).is_ok());
        
        // Verify state transition
        assert_eq!(state_machine.current_state(), HandshakeState::WaitServerHello);
        assert_eq!(state_machine.transcript().message_count(), 1);
        
        // Client random should be extracted
        assert!(state_machine.client_random.is_some());
        assert_eq!(state_machine.client_random.unwrap(), client_hello.random);
        
        // Client private key should be generated
        assert!(state_machine.client_private_key.is_some());
    }

    #[test]
    fn test_server_finished_hmac_validation() {
        // This test validates the Server Finished HMAC verification implementation
        // It first computes the expected HMAC, then tests both valid and invalid cases
        
        let crypto_provider = NativeCryptoProvider::new();
        let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider.clone());
        
        // Setup handshake state up to ServerFinished validation point
        setup_handshake_to_server_finished(&mut state_machine);
        
        // Compute the expected HMAC for this handshake state
        let transcript_hash = state_machine.transcript.current_hash();
        let traffic_secrets = state_machine.key_schedule.derive_handshake_traffic_secrets(&transcript_hash).unwrap();
        let finished_key = state_machine.key_schedule.derive_finished_key(&traffic_secrets.server_handshake_traffic_secret).unwrap();
        let expected_verify_data = crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash).unwrap();
        
        // Test with correct HMAC - should succeed
        let valid_server_finished = Finished {
            verify_data: expected_verify_data.clone(),
        };
        
        let sf_msg = valid_server_finished.to_handshake_message().unwrap();
        let result = state_machine.process_inbound_message(&sf_msg);
        
        assert!(result.is_ok(), "Server Finished HMAC validation should pass with correct verify_data");
        assert_eq!(state_machine.current_state(), HandshakeState::WaitFlight2);
        
        // Test with invalid HMAC - should fail
        let invalid_server_finished = Finished {
            verify_data: vec![0x00; 32], // Invalid HMAC
        };
        
        // Reset state machine to test invalid case  
        let mut state_machine2 = EnhancedHandshakeStateMachine::new(NativeCryptoProvider::new());
        setup_handshake_to_server_finished(&mut state_machine2);
        
        let invalid_sf_msg = invalid_server_finished.to_handshake_message().unwrap();
        let result = state_machine2.process_inbound_message(&invalid_sf_msg);
        
        // Should fail with invalid HMAC
        assert!(result.is_err(), "Server Finished HMAC validation should fail with invalid verify_data");
        assert!(matches!(result.unwrap_err(), ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidFinishedMessage)));
    }

    #[test]
    fn test_client_finished_hmac_generation() {
        // RED: This test should fail until we implement real Client Finished HMAC generation
        // This test validates that the client can generate a proper Finished message HMAC
        
        let crypto_provider = NativeCryptoProvider::new();
        let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider.clone());
        
        // Setup handshake state through server finished (ready for client finished)
        setup_handshake_through_server_finished(&mut state_machine);
        
        // Test that we can generate a valid client Finished message
        let client_finished = state_machine.generate_client_finished().unwrap();
        
        // Verify the generated Finished message has correct structure
        assert_eq!(client_finished.verify_data.len(), 32, "Client Finished verify_data should be 32 bytes");
        assert_ne!(client_finished.verify_data, vec![0u8; 32], "Client Finished verify_data should not be all zeros");
        
        // Test that the generated HMAC can be validated by computing it separately
        let transcript_hash = state_machine.transcript.current_hash();
        let traffic_secrets = state_machine.key_schedule.derive_handshake_traffic_secrets(&transcript_hash).unwrap();
        let finished_key = state_machine.key_schedule.derive_finished_key(&traffic_secrets.client_handshake_traffic_secret).unwrap();
        let expected_verify_data = crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash).unwrap();
        
        assert_eq!(client_finished.verify_data, expected_verify_data, 
                   "Generated Client Finished HMAC should match independently computed HMAC");
        
        // Test that the client finished can be processed (self-validation)
        let cf_msg = client_finished.to_handshake_message().unwrap();
        let result = state_machine.process_outbound_message(&cf_msg);
        
        assert!(result.is_ok(), "Client should be able to process its own generated Finished message");
        assert_eq!(state_machine.current_state(), HandshakeState::Connected);
        assert!(state_machine.is_handshake_complete());
    }

    #[test]
    fn test_certificate_verify_signature_validation() {
        // RED: This test should fail until we implement real CertificateVerify signature validation
        // This test validates that the server's CertificateVerify signature is properly verified
        // according to RFC 8446 Section 4.4.3
        
        let crypto_provider = NativeCryptoProvider::new();
        let mut state_machine = EnhancedHandshakeStateMachine::new(crypto_provider.clone());
        
        // Setup handshake state up to CertificateVerify validation point
        setup_handshake_to_certificate_verify(&mut state_machine);
        
        // Create a CertificateVerify message with a real signature over the transcript
        // Note: This will be a mock signature for now, but the validation logic should be real
        let transcript_hash = state_machine.transcript.current_hash();
        
        // Construct the signature context per RFC 8446 Section 4.4.3:
        // " " * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        let mut signature_context = Vec::new();
        signature_context.extend_from_slice(&[0x20u8; 64]); // 64 spaces
        signature_context.extend_from_slice(b"TLS 1.3, server CertificateVerify");
        signature_context.push(0x00); // separator byte
        signature_context.extend_from_slice(&transcript_hash);
        
        // For now, create a mock signature (in a real implementation, this would be computed from a test certificate)
        let mock_signature = vec![
            0x30, 0x44, 0x02, 0x20, // ECDSA signature ASN.1 DER format
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0x02, 0x20,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
            0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99,
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        ];
        
        let certificate_verify = CertificateVerify {
            algorithm: SignatureScheme::EcdsaSecp256r1Sha256,
            signature: mock_signature,
        };
        
        let cv_msg = certificate_verify.to_handshake_message().unwrap();
        
        // Test with real certificate and mock signature (should fail)
        let result = state_machine.process_inbound_message(&cv_msg);
        
        // With real certificate validation and mock signature, this should fail
        // This is the correct behavior - invalid signatures should be rejected
        assert!(result.is_err(), "CertificateVerify processing should fail with invalid mock signature");
        
        // Verify it fails for the right reason (signature validation)
        match result.unwrap_err() {
            ZkTlsError::ProtocolError(crate::errors::ProtocolError::InvalidStateTransition(msg)) => {
                assert!(msg.to_lowercase().contains("signature"), "Should fail due to signature validation, got: {}", msg);
            },
            other => panic!("Expected signature validation error, got: {:?}", other),
        }
        
        // State should remain unchanged since verification failed
        assert_eq!(state_machine.current_state(), HandshakeState::WaitCertificateVerify);
        
        // TODO: Add separate tests for real signature validation:
        // 1. Test with real certificate/signature pairs that should pass validation
        // 2. Test with real certificate but invalid signature that should fail
        // 3. Different signature schemes validation  
        // 4. Signature context construction validation with known test vectors
    }

    // Helper function to set up handshake state through server finished (ready for client finished)
    fn setup_handshake_through_server_finished(state_machine: &mut EnhancedHandshakeStateMachine<NativeCryptoProvider>) {
        // First setup to server finished validation point
        setup_handshake_to_server_finished(state_machine);
        
        // Process a valid server finished message
        let crypto_provider = NativeCryptoProvider::new();
        let transcript_hash = state_machine.transcript.current_hash();
        let traffic_secrets = state_machine.key_schedule.derive_handshake_traffic_secrets(&transcript_hash).unwrap();
        let finished_key = state_machine.key_schedule.derive_finished_key(&traffic_secrets.server_handshake_traffic_secret).unwrap();
        let expected_verify_data = crypto_provider.hkdf_extract_sha256(&finished_key, &transcript_hash).unwrap();
        
        let server_finished = Finished {
            verify_data: expected_verify_data,
        };
        
        let sf_msg = server_finished.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&sf_msg).unwrap();
        
        assert_eq!(state_machine.current_state(), HandshakeState::WaitFlight2);
    }

    // Helper function to set up handshake state up to CertificateVerify validation point  
    fn setup_handshake_to_certificate_verify(state_machine: &mut EnhancedHandshakeStateMachine<NativeCryptoProvider>) {
        // Setup up to Certificate message
        let client_hello = ClientHello {
            legacy_version: 0x0303,
            random: hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301], // TLS_AES_128_GCM_SHA256
            legacy_compression_methods: vec![0x00],
            extensions: create_test_client_extensions(),
        };
        
        let ch_msg = client_hello.to_handshake_message().unwrap();
        state_machine.process_outbound_message(&ch_msg).unwrap();
        
        // ServerHello with known key share for deterministic shared secret
        let server_hello = ServerHello {
            legacy_version: 0x0303,
            random: hex!("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301,
            legacy_compression_method: 0x00,
            extensions: create_test_server_extensions(),
        };
        
        let sh_msg = server_hello.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&sh_msg).unwrap();
        
        // EncryptedExtensions
        let ee_msg = HandshakeMessage::new(
            HandshakeType::EncryptedExtensions,
            vec![0x00, 0x00] // Empty extensions
        ).unwrap();
        state_machine.process_inbound_message(&ee_msg).unwrap();
        
        // Certificate
        let certificate = Certificate {
            certificate_request_context: vec![],
            certificate_list: create_test_certificate_list(),
        };
        let cert_msg = certificate.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&cert_msg).unwrap();
        
        // Now state machine is ready for CertificateVerify validation
        assert_eq!(state_machine.current_state(), HandshakeState::WaitCertificateVerify);
    }

    // Helper function to set up handshake state up to Certificate processing (before CertificateVerify)
    fn setup_handshake_to_certificate(state_machine: &mut EnhancedHandshakeStateMachine<NativeCryptoProvider>) {
        // Create known handshake messages that produce deterministic transcript
        let client_hello = ClientHello {
            legacy_version: 0x0303,
            random: hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301], // TLS_AES_128_GCM_SHA256
            legacy_compression_methods: vec![0x00],
            extensions: create_test_client_extensions(),
        };
        
        let ch_msg = client_hello.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&ch_msg).unwrap();
        
        // ServerHello with deterministic values
        let server_hello = ServerHello {
            legacy_version: 0x0303,
            random: hex!("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            legacy_compression_method: 0x00,
            extensions: create_test_server_extensions(),
        };
        
        let sh_msg = server_hello.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&sh_msg).unwrap();
        
        // EncryptedExtensions
        let ee_msg = HandshakeMessage::new(
            HandshakeType::EncryptedExtensions,
            vec![0x00, 0x00] // Empty extensions
        ).unwrap();
        state_machine.process_inbound_message(&ee_msg).unwrap();
        
        // Certificate
        let certificate = Certificate {
            certificate_request_context: vec![],
            certificate_list: create_test_certificate_list(),
        };
        let cert_msg = certificate.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&cert_msg).unwrap();
        
        // Now state machine is ready for CertificateVerify validation
        assert_eq!(state_machine.current_state(), HandshakeState::WaitCertificateVerify);
    }

    // Helper function to set up handshake state up to Server Finished validation point
    fn setup_handshake_to_server_finished(state_machine: &mut EnhancedHandshakeStateMachine<NativeCryptoProvider>) {
        // Create known handshake messages that produce deterministic transcript
        let client_hello = ClientHello {
            legacy_version: 0x0303,
            random: hex!("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301], // TLS_AES_128_GCM_SHA256
            legacy_compression_methods: vec![0x00],
            extensions: create_test_client_extensions(),
        };
        
        let ch_msg = client_hello.to_handshake_message().unwrap();
        state_machine.process_outbound_message(&ch_msg).unwrap();
        
        // ServerHello with known key share for deterministic shared secret
        let server_hello = ServerHello {
            legacy_version: 0x0303,
            random: hex!("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"),
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301,
            legacy_compression_method: 0x00,
            extensions: create_test_server_extensions(),
        };
        
        let sh_msg = server_hello.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&sh_msg).unwrap();
        
        // EncryptedExtensions
        let ee_msg = HandshakeMessage::new(
            HandshakeType::EncryptedExtensions,
            vec![0x00, 0x00] // Empty extensions
        ).unwrap();
        state_machine.process_inbound_message(&ee_msg).unwrap();
        
        // Certificate
        let certificate = Certificate {
            certificate_request_context: vec![],
            certificate_list: create_test_certificate_list(),
        };
        let cert_msg = certificate.to_handshake_message().unwrap();
        state_machine.process_inbound_message(&cert_msg).unwrap();
        
        // CertificateVerify - For HMAC tests, we need the transcript but don't need signature validation
        // Add the CertificateVerify message to transcript manually without signature verification
        let cv_data = create_test_certificate_verify_data();
        let cv_msg = HandshakeMessage::new(
            HandshakeType::CertificateVerify,
            cv_data.clone()
        ).unwrap();
        
        // Add to transcript hash manually (this is what process_inbound_message would do)
        state_machine.transcript.add_message(&cv_msg).unwrap();
        
        // Manually transition state without signature verification for these tests
        state_machine.current_state = HandshakeState::WaitServerFinished;
        
        // Now state machine is ready for Server Finished validation
        assert_eq!(state_machine.current_state(), HandshakeState::WaitServerFinished);
    }
    
    fn create_test_client_extensions() -> Vec<u8> {
        // Deterministic client extensions for testing
        vec![
            // supported_versions extension
            0x00, 0x2b, // extension_type = supported_versions (43)
            0x00, 0x03, // length = 3
            0x02,       // versions length = 2  
            0x03, 0x04, // TLS 1.3
            
            // key_share extension with known X25519 key
            0x00, 0x33, // extension_type = key_share (51)
            0x00, 0x24, // length = 36
            0x00, 0x22, // key_share length = 34
            0x00, 0x1d, // group = x25519 (29)
            0x00, 0x20, // key_exchange length = 32
            // Known X25519 public key for deterministic testing
            0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 
            0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38,
            0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 
            0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
        ]
    }
    
    fn create_test_server_extensions() -> Vec<u8> {
        // Deterministic server extensions for testing
        vec![
            // supported_versions extension
            0x00, 0x2b, // extension_type = supported_versions (43)
            0x00, 0x02, // length = 2
            0x03, 0x04, // TLS 1.3
            
            // key_share extension with known X25519 key (ServerHello format - single KeyShareEntry)
            0x00, 0x33, // extension_type = key_share (51)
            0x00, 0x24, // length = 36 (2 + 2 + 32 = group + key_length + key data)
            0x00, 0x1d, // group = x25519 (29)
            0x00, 0x20, // key_exchange length = 32
            // Known X25519 public key for deterministic testing
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
        ]
    }
    
    fn create_test_certificate_list() -> Vec<u8> {
        // Mock certificate list for testing with valid structure
        // For tests that don't require real signature validation, use minimal valid ASN.1
        let mock_cert_data = create_minimal_valid_certificate();
        
        let mut result = Vec::new();
        
        // Certificate data length (3 bytes)
        let cert_len = mock_cert_data.len() as u32;
        result.extend_from_slice(&cert_len.to_be_bytes()[1..4]); // 3 bytes
        
        // Certificate data
        result.extend_from_slice(&mock_cert_data);
        
        // Extensions length (2 bytes) - empty extensions
        result.extend_from_slice(&[0x00, 0x00]);
        
        result
    }
    
    fn create_minimal_valid_certificate() -> Vec<u8> {
        // Use real ECDSA certificate from test fixtures for production-quality testing
        // This certificate will properly parse and can be used for signature verification tests
        include_bytes!("../../tests/fixtures/certificates/test_ecdsa_cert.der").to_vec()
    }
    
    fn create_test_certificate_verify_data() -> Vec<u8> {
        // Mock CertificateVerify data for testing with ECDSA to match test certificate
        vec![
            0x04, 0x03, // signature_scheme = ecdsa_secp256r1_sha256
            0x00, 0x40, // signature length = 64
            // Mock signature data (64 bytes)
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
            0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
        ]
    }
}