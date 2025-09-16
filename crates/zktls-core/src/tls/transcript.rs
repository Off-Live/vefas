//! TLS 1.3 Transcript Hash Management (RFC 8446, Section 4.4.1)
//!
//! This module handles the cryptographic transcript hash that is maintained throughout
//! the TLS 1.3 handshake. The transcript hash is used for:
//! - Key schedule derivation (HKDF-Expand-Label)
//! - Finished message verification
//! - Certificate verification signatures
//! - Session resumption ticket generation
//!
//! The transcript hash is computed as:
//! ```text
//! Transcript-Hash(M1, M2, ... Mn) = Hash(M1 || M2 || ... || Mn)
//! ```
//! Where Hash is SHA-256 for the cipher suites we support.

use crate::errors::{ZkTlsError, ZkTlsResult};
use crate::tls::handshake::HandshakeMessage;
use alloc::{vec::Vec, format};
use serde::{Deserialize, Serialize};

/// SHA-256 hash size in bytes
const HASH_SIZE: usize = 32;

/// TLS 1.3 transcript hash manager
/// 
/// Maintains a running cryptographic hash of all handshake messages
/// as they are sent and received during the TLS 1.3 handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptHash {
    /// SHA-256 hasher state (we'll use a simple approach for now)
    messages: Vec<Vec<u8>>,
    /// Cache of computed hashes at each message count
    hash_cache: Vec<[u8; HASH_SIZE]>,
}

impl TranscriptHash {
    /// Create a new empty transcript hash
    pub fn new() -> Self {
        Self {
            messages: Vec::new(),
            hash_cache: Vec::new(),
        }
    }
    
    /// Add a handshake message to the transcript
    /// 
    /// This method adds the complete handshake message (including the 4-byte header)
    /// to the transcript and updates the running hash.
    pub fn add_message(&mut self, message: &HandshakeMessage) -> ZkTlsResult<()> {
        // Serialize the complete handshake message (header + payload)
        let serialized = message.serialize();
        
        // Add to our message list
        self.messages.push(serialized);
        
        // Compute the new cumulative hash
        let new_hash = self.compute_hash_up_to(self.messages.len())?;
        self.hash_cache.push(new_hash);
        
        Ok(())
    }
    
    /// Get the current transcript hash (hash of all messages so far)
    pub fn current_hash(&self) -> [u8; HASH_SIZE] {
        if let Some(last_hash) = self.hash_cache.last() {
            *last_hash
        } else {
            // Empty transcript hash is SHA-256 of empty string
            self.compute_empty_hash()
        }
    }
    
    /// Get the transcript hash at a specific message count
    /// 
    /// This is useful for key derivation where we need the transcript hash
    /// at specific points in the handshake (e.g., after ServerHello).
    pub fn hash_at_message(&self, message_count: usize) -> ZkTlsResult<[u8; HASH_SIZE]> {
        if message_count == 0 {
            return Ok(self.compute_empty_hash());
        }
        
        if message_count > self.messages.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Requested hash at message {} but only {} messages in transcript", 
                       message_count, self.messages.len())
            ));
        }
        
        // Check if we have it cached
        if let Some(cached_hash) = self.hash_cache.get(message_count - 1) {
            Ok(*cached_hash)
        } else {
            // Compute and cache it
            self.compute_hash_up_to(message_count)
        }
    }
    
    /// Get the number of messages in the transcript
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }
    
    /// Get the raw concatenated transcript data up to a specific message count
    /// 
    /// This is useful for debugging and testing purposes.
    pub fn transcript_data_up_to(&self, message_count: usize) -> ZkTlsResult<Vec<u8>> {
        if message_count > self.messages.len() {
            return Err(ZkTlsError::InvalidTlsMessage(
                format!("Requested transcript up to message {} but only {} messages available", 
                       message_count, self.messages.len())
            ));
        }
        
        let mut transcript = Vec::new();
        for i in 0..message_count {
            transcript.extend_from_slice(&self.messages[i]);
        }
        
        Ok(transcript)
    }
    
    /// Clear the transcript (used for testing)
    pub fn clear(&mut self) {
        self.messages.clear();
        self.hash_cache.clear();
    }
    
    /// Check if the transcript is empty
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
    
    // Private helper methods
    
    /// Compute SHA-256 hash of messages up to a specific count
    fn compute_hash_up_to(&self, message_count: usize) -> ZkTlsResult<[u8; HASH_SIZE]> {
        let transcript_data = self.transcript_data_up_to(message_count)?;
        Ok(self.sha256(&transcript_data))
    }
    
    /// Compute SHA-256 of empty string (initial transcript hash)
    fn compute_empty_hash(&self) -> [u8; HASH_SIZE] {
        self.sha256(&[])
    }
    
    /// Compute SHA-256 hash using platform-appropriate method
    /// 
    /// In zkVM environments, this should use the SHA-256 precompile.
    /// For native execution, we use a software implementation.
    fn sha256(&self, data: &[u8]) -> [u8; HASH_SIZE] {
        #[cfg(feature = "sp1")]
        {
            // Use SP1 SHA-256 precompile for zkVM execution
            // TODO: Implement SP1 SHA-256 precompile usage
            // For now, fall back to software implementation
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().into()
        }
        
        #[cfg(not(feature = "sp1"))]
        {
            // Use software SHA-256 for native execution
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            hasher.finalize().into()
        }
    }
}

impl Default for TranscriptHash {
    fn default() -> Self {
        Self::new()
    }
}

/// Key schedule context for TLS 1.3 key derivation
/// 
/// Contains transcript hash values needed at different stages of key derivation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyScheduleContext {
    /// Transcript hash after ClientHello + ServerHello
    pub client_server_hello_hash: [u8; HASH_SIZE],
    /// Transcript hash after all handshake messages except Finished
    pub handshake_context_hash: [u8; HASH_SIZE],
    /// Transcript hash after Client Finished (for application traffic keys)
    pub application_context_hash: [u8; HASH_SIZE],
}

impl KeyScheduleContext {
    /// Extract key schedule context from a transcript at the completion of handshake
    pub fn from_complete_transcript(transcript: &TranscriptHash) -> ZkTlsResult<Self> {
        if transcript.message_count() < 7 {
            return Err(ZkTlsError::InvalidTlsMessage(
                "Transcript must contain at least 7 messages for complete handshake".into()
            ));
        }
        
        // Assuming standard TLS 1.3 handshake message order:
        // 1. ClientHello
        // 2. ServerHello
        // 3. EncryptedExtensions
        // 4. Certificate
        // 5. CertificateVerify
        // 6. Server Finished
        // 7. Client Finished
        
        let client_server_hello_hash = transcript.hash_at_message(2)?;
        let handshake_context_hash = transcript.hash_at_message(6)?; // Before Client Finished
        let application_context_hash = transcript.hash_at_message(7)?; // After Client Finished
        
        Ok(KeyScheduleContext {
            client_server_hello_hash,
            handshake_context_hash,
            application_context_hash,
        })
    }
    
    /// Create a context for testing purposes
    pub fn mock() -> Self {
        KeyScheduleContext {
            client_server_hello_hash: [0x01; HASH_SIZE],
            handshake_context_hash: [0x02; HASH_SIZE],
            application_context_hash: [0x03; HASH_SIZE],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::handshake::{HandshakeType, ClientHello, ServerHello};
    use hex_literal::hex;
    use alloc::vec;
    
    #[test]
    fn test_empty_transcript_hash() {
        let transcript = TranscriptHash::new();
        
        // Empty transcript should have SHA-256 of empty string
        let empty_hash = transcript.current_hash();
        let expected_empty_hash = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(empty_hash, expected_empty_hash);
        
        assert_eq!(transcript.message_count(), 0);
        assert!(transcript.is_empty());
    }
    
    #[test]
    fn test_single_message_transcript() {
        let mut transcript = TranscriptHash::new();
        
        // Create a simple handshake message
        let payload = vec![0x03, 0x03, 0x01, 0x02]; // Simple payload
        let message = HandshakeMessage::new(HandshakeType::ClientHello, payload).unwrap();
        
        // Add message to transcript
        transcript.add_message(&message).unwrap();
        
        // Should now have 1 message
        assert_eq!(transcript.message_count(), 1);
        assert!(!transcript.is_empty());
        
        // Hash should be different from empty
        let hash_after_message = transcript.current_hash();
        let empty_hash = TranscriptHash::new().current_hash();
        assert_ne!(hash_after_message, empty_hash);
        
        // Should be able to get hash at message 1
        let hash_at_1 = transcript.hash_at_message(1).unwrap();
        assert_eq!(hash_at_1, hash_after_message);
    }
    
    #[test]
    fn test_multiple_message_transcript() {
        let mut transcript = TranscriptHash::new();
        
        // Create ClientHello
        let client_hello = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            legacy_session_id: vec![],
            cipher_suites: vec![0x1301],
            legacy_compression_methods: vec![0x00],
            extensions: vec![],
        };
        
        let ch_msg = client_hello.to_handshake_message().unwrap();
        transcript.add_message(&ch_msg).unwrap();
        
        let hash_after_ch = transcript.current_hash();
        
        // Create ServerHello
        let server_hello = ServerHello {
            legacy_version: 0x0303,
            random: [1u8; 32],
            legacy_session_id_echo: vec![],
            cipher_suite: 0x1301,
            legacy_compression_method: 0x00,
            extensions: vec![],
        };
        
        let sh_msg = server_hello.to_handshake_message().unwrap();
        transcript.add_message(&sh_msg).unwrap();
        
        let hash_after_sh = transcript.current_hash();
        
        // Hashes should be different
        assert_ne!(hash_after_ch, hash_after_sh);
        
        // Should have 2 messages
        assert_eq!(transcript.message_count(), 2);
        
        // Should be able to get hash at each message
        assert_eq!(transcript.hash_at_message(1).unwrap(), hash_after_ch);
        assert_eq!(transcript.hash_at_message(2).unwrap(), hash_after_sh);
        assert_eq!(transcript.current_hash(), hash_after_sh);
    }
    
    #[test]
    fn test_transcript_data_extraction() {
        let mut transcript = TranscriptHash::new();
        
        // Add two simple messages
        let msg1 = HandshakeMessage::new(
            HandshakeType::ClientHello, 
            vec![0x01, 0x02]
        ).unwrap();
        
        let msg2 = HandshakeMessage::new(
            HandshakeType::ServerHello,
            vec![0x03, 0x04]
        ).unwrap();
        
        transcript.add_message(&msg1).unwrap();
        transcript.add_message(&msg2).unwrap();
        
        // Get transcript data up to message 1
        let data_1 = transcript.transcript_data_up_to(1).unwrap();
        let expected_1 = msg1.serialize();
        assert_eq!(data_1, expected_1);
        
        // Get transcript data up to message 2
        let data_2 = transcript.transcript_data_up_to(2).unwrap();
        let mut expected_2 = msg1.serialize();
        expected_2.extend_from_slice(&msg2.serialize());
        assert_eq!(data_2, expected_2);
        
        // Requesting beyond available messages should fail
        assert!(transcript.transcript_data_up_to(3).is_err());
    }
    
    #[test]
    fn test_hash_consistency() {
        let mut transcript1 = TranscriptHash::new();
        let mut transcript2 = TranscriptHash::new();
        
        // Create identical messages
        let message = HandshakeMessage::new(
            HandshakeType::ClientHello,
            vec![0x01, 0x02, 0x03, 0x04]
        ).unwrap();
        
        // Add to both transcripts
        transcript1.add_message(&message).unwrap();
        transcript2.add_message(&message).unwrap();
        
        // Should produce identical hashes
        assert_eq!(transcript1.current_hash(), transcript2.current_hash());
        assert_eq!(transcript1.hash_at_message(1).unwrap(), transcript2.hash_at_message(1).unwrap());
    }
    
    #[test]
    fn test_clear_transcript() {
        let mut transcript = TranscriptHash::new();
        
        // Add a message
        let message = HandshakeMessage::new(
            HandshakeType::ClientHello,
            vec![0x01, 0x02]
        ).unwrap();
        
        transcript.add_message(&message).unwrap();
        assert_eq!(transcript.message_count(), 1);
        assert!(!transcript.is_empty());
        
        // Clear transcript
        transcript.clear();
        assert_eq!(transcript.message_count(), 0);
        assert!(transcript.is_empty());
        
        // Hash should be back to empty hash
        let empty_hash = TranscriptHash::new().current_hash();
        assert_eq!(transcript.current_hash(), empty_hash);
    }
    
    #[test]
    fn test_key_schedule_context_extraction() {
        let mut transcript = TranscriptHash::new();
        
        // Add 7 mock handshake messages (full TLS 1.3 handshake)
        for i in 1..=7 {
            let msg_type = match i {
                1 => HandshakeType::ClientHello,
                2 => HandshakeType::ServerHello,
                3 => HandshakeType::EncryptedExtensions,
                4 => HandshakeType::Certificate,
                5 => HandshakeType::CertificateVerify,
                6 | 7 => HandshakeType::Finished,
                _ => unreachable!(),
            };
            
            let message = HandshakeMessage::new(
                msg_type,
                vec![i as u8] // Simple payload with message index
            ).unwrap();
            
            transcript.add_message(&message).unwrap();
        }
        
        // Extract key schedule context
        let context = KeyScheduleContext::from_complete_transcript(&transcript).unwrap();
        
        // Verify we have the correct hashes
        assert_eq!(context.client_server_hello_hash, transcript.hash_at_message(2).unwrap());
        assert_eq!(context.handshake_context_hash, transcript.hash_at_message(6).unwrap());
        assert_eq!(context.application_context_hash, transcript.hash_at_message(7).unwrap());
        
        // All hashes should be different
        assert_ne!(context.client_server_hello_hash, context.handshake_context_hash);
        assert_ne!(context.handshake_context_hash, context.application_context_hash);
    }
    
    #[test]
    fn test_key_schedule_context_insufficient_messages() {
        let mut transcript = TranscriptHash::new();
        
        // Add only 3 messages (insufficient for complete handshake)
        for i in 1..=3 {
            let message = HandshakeMessage::new(
                HandshakeType::ClientHello,
                vec![i as u8]
            ).unwrap();
            
            transcript.add_message(&message).unwrap();
        }
        
        // Should fail to extract context
        assert!(KeyScheduleContext::from_complete_transcript(&transcript).is_err());
    }
    
    #[test]
    fn test_hash_determinism() {
        // Create multiple transcripts with identical messages and verify deterministic hashing
        let messages = vec![
            vec![0x01, 0x02, 0x03, 0x04],
            vec![0x05, 0x06, 0x07, 0x08],
            vec![0x09, 0x0a, 0x0b, 0x0c],
        ];
        
        let mut transcript1 = TranscriptHash::new();
        let mut transcript2 = TranscriptHash::new();
        
        for (i, payload) in messages.iter().enumerate() {
            let msg_type = match i % 3 {
                0 => HandshakeType::ClientHello,
                1 => HandshakeType::ServerHello,
                _ => HandshakeType::Certificate,
            };
            
            let message = HandshakeMessage::new(msg_type, payload.clone()).unwrap();
            
            transcript1.add_message(&message).unwrap();
            transcript2.add_message(&message).unwrap();
        }
        
        // Verify identical results
        assert_eq!(transcript1.current_hash(), transcript2.current_hash());
        for i in 1..=messages.len() {
            assert_eq!(
                transcript1.hash_at_message(i).unwrap(),
                transcript2.hash_at_message(i).unwrap()
            );
        }
    }
}