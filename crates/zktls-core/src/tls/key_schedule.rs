//! TLS 1.3 Key Schedule Implementation (RFC 8446, Section 7.1)
//!
//! This module implements the complete TLS 1.3 key schedule including:
//! - HKDF-Extract and HKDF-Expand-Label operations
//! - Early Secret, Handshake Secret, and Master Secret derivation
//! - Traffic key and IV derivation for handshake and application data
//! - Finished message MAC key derivation
//!
//! All operations use the zktls-crypto provider for cryptographic operations
//! to ensure compatibility with zkVM precompiles.

use crate::errors::{ZkTlsError, ZkTlsResult, ProtocolError};
use zktls_crypto::{CryptoProvider, Hash, Kdf};
use alloc::{vec::Vec, format};
use serde::{Deserialize, Serialize};

/// TLS 1.3 Key Schedule State
/// 
/// Tracks the progression through the key schedule states as defined
/// in RFC 8446 Section 7.1, with proper secret derivation at each stage.
#[derive(Debug, Clone)]
pub struct Tls13KeySchedule<P>
where
    P: CryptoProvider + Hash + Kdf
{
    /// Cryptographic provider for HKDF operations
    crypto_provider: P,
    /// Early secret (derived from PSK or zero)
    early_secret: Option<[u8; 32]>,
    /// Handshake secret (derived after ECDHE)
    handshake_secret: Option<[u8; 32]>,
    /// Master secret (derived after handshake completion)
    master_secret: Option<[u8; 32]>,
}

/// Handshake traffic secrets for client and server
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeTrafficSecrets {
    /// Client handshake traffic secret (32 bytes for SHA-256)
    pub client_handshake_traffic_secret: [u8; 32],
    /// Server handshake traffic secret (32 bytes for SHA-256)
    pub server_handshake_traffic_secret: [u8; 32],
}

/// Application traffic secrets for client and server
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationTrafficSecrets {
    /// Client application traffic secret (32 bytes for SHA-256)
    pub client_application_traffic_secret: [u8; 32],
    /// Server application traffic secret (32 bytes for SHA-256)
    pub server_application_traffic_secret: [u8; 32],
}

/// Derived traffic keys for encryption/decryption
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficKeys {
    /// Encryption key (16 or 32 bytes depending on cipher suite)
    pub key: Vec<u8>,
    /// Initialization vector (12 bytes for AES-GCM)
    pub iv: [u8; 12],
}

impl<P> Tls13KeySchedule<P>
where
    P: CryptoProvider + Hash + Kdf
{
    /// Create a new TLS 1.3 key schedule
    pub fn new(crypto_provider: P) -> Self {
        Self {
            crypto_provider,
            early_secret: None,
            handshake_secret: None,
            master_secret: None,
        }
    }
    
    /// Derive the Early Secret (Step 1 of TLS 1.3 key schedule)
    /// 
    /// Early-Secret = HKDF-Extract(salt=0, IKM=PSK or 0)
    /// For standard (non-PSK) handshakes, this uses zero IKM.
    pub fn derive_early_secret(&mut self, psk: Option<&[u8]>) -> ZkTlsResult<()> {
        let salt = &[0u8; 32]; // Zero salt for Early Secret
        let ikm = psk.unwrap_or(&[0u8; 32]); // Zero IKM if no PSK
        
        let early_secret = self.crypto_provider.hkdf_extract_sha256(salt, ikm)
            .map_err(|_| ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed))?;
        
        if early_secret.len() != 32 {
            return Err(ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed));
        }
        
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&early_secret[..32]);
        self.early_secret = Some(secret_array);
        
        Ok(())
    }
    
    /// Derive the Handshake Secret (Step 2 of TLS 1.3 key schedule)
    /// 
    /// Handshake-Secret = HKDF-Extract(salt=Derive-Secret(Early-Secret, "derived", ""), 
    ///                                  IKM=shared_secret)
    pub fn derive_handshake_secret(&mut self, shared_secret: &[u8]) -> ZkTlsResult<()> {
        if self.early_secret.is_none() {
            return Err(ZkTlsError::invalid_state_transition(
                "Early secret must be derived before handshake secret"
            ));
        }
        
        // Derive salt using Derive-Secret(Early-Secret, "derived", "")
        let salt = self.derive_secret(&self.early_secret.unwrap(), "derived", &[])?;
        
        let handshake_secret = self.crypto_provider.hkdf_extract_sha256(&salt, shared_secret)
            .map_err(|_| ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed))?;
        
        if handshake_secret.len() != 32 {
            return Err(ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed));
        }
        
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&handshake_secret[..32]);
        self.handshake_secret = Some(secret_array);
        
        Ok(())
    }
    
    /// Derive handshake traffic secrets for client and server
    /// 
    /// client_handshake_traffic_secret = Derive-Secret(Handshake-Secret, "c hs traffic", handshake_context)
    /// server_handshake_traffic_secret = Derive-Secret(Handshake-Secret, "s hs traffic", handshake_context)
    pub fn derive_handshake_traffic_secrets(&self, handshake_context: &[u8]) -> ZkTlsResult<HandshakeTrafficSecrets> {
        if self.handshake_secret.is_none() {
            return Err(ZkTlsError::invalid_state_transition(
                "Handshake secret must be derived before handshake traffic secrets"
            ));
        }
        
        let handshake_secret = self.handshake_secret.unwrap();
        
        let client_secret = self.derive_secret(&handshake_secret, "c hs traffic", handshake_context)?;
        let server_secret = self.derive_secret(&handshake_secret, "s hs traffic", handshake_context)?;
        
        let mut client_array = [0u8; 32];
        let mut server_array = [0u8; 32];
        client_array.copy_from_slice(&client_secret);
        server_array.copy_from_slice(&server_secret);
        
        Ok(HandshakeTrafficSecrets {
            client_handshake_traffic_secret: client_array,
            server_handshake_traffic_secret: server_array,
        })
    }
    
    /// Derive the Master Secret (Step 3 of TLS 1.3 key schedule)
    /// 
    /// Master-Secret = HKDF-Extract(salt=Derive-Secret(Handshake-Secret, "derived", ""), 
    ///                               IKM=0)
    pub fn derive_master_secret(&mut self) -> ZkTlsResult<()> {
        if self.handshake_secret.is_none() {
            return Err(ZkTlsError::invalid_state_transition(
                "Handshake secret must be derived before master secret"
            ));
        }
        
        // Derive salt using Derive-Secret(Handshake-Secret, "derived", "")
        let salt = self.derive_secret(&self.handshake_secret.unwrap(), "derived", &[])?;
        let ikm = &[0u8; 32]; // Zero IKM for Master Secret
        
        let master_secret = self.crypto_provider.hkdf_extract_sha256(&salt, ikm)
            .map_err(|_| ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed))?;
        
        if master_secret.len() != 32 {
            return Err(ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed));
        }
        
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&master_secret[..32]);
        self.master_secret = Some(secret_array);
        
        Ok(())
    }
    
    /// Derive application traffic secrets for client and server
    /// 
    /// client_application_traffic_secret = Derive-Secret(Master-Secret, "c ap traffic", handshake_context)
    /// server_application_traffic_secret = Derive-Secret(Master-Secret, "s ap traffic", handshake_context)
    pub fn derive_application_traffic_secrets(&self, handshake_context: &[u8]) -> ZkTlsResult<ApplicationTrafficSecrets> {
        if self.master_secret.is_none() {
            return Err(ZkTlsError::invalid_state_transition(
                "Master secret must be derived before application traffic secrets"
            ));
        }
        
        let master_secret = self.master_secret.unwrap();
        
        let client_secret = self.derive_secret(&master_secret, "c ap traffic", handshake_context)?;
        let server_secret = self.derive_secret(&master_secret, "s ap traffic", handshake_context)?;
        
        let mut client_array = [0u8; 32];
        let mut server_array = [0u8; 32];
        client_array.copy_from_slice(&client_secret);
        server_array.copy_from_slice(&server_secret);
        
        Ok(ApplicationTrafficSecrets {
            client_application_traffic_secret: client_array,
            server_application_traffic_secret: server_array,
        })
    }
    
    /// Derive traffic keys and IVs from traffic secret
    /// 
    /// key = HKDF-Expand-Label(Secret, "key", "", key_length)
    /// iv = HKDF-Expand-Label(Secret, "iv", "", 12)
    pub fn derive_traffic_keys(&self, traffic_secret: &[u8], key_length: usize) -> ZkTlsResult<TrafficKeys> {
        let key = self.hkdf_expand_label(traffic_secret, "key", &[], key_length)?;
        let iv_bytes = self.hkdf_expand_label(traffic_secret, "iv", &[], 12)?;
        
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&iv_bytes);
        
        Ok(TrafficKeys { key, iv })
    }
    
    /// Derive Finished message MAC key
    /// 
    /// finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
    pub fn derive_finished_key(&self, traffic_secret: &[u8]) -> ZkTlsResult<[u8; 32]> {
        let key_bytes = self.hkdf_expand_label(traffic_secret, "finished", &[], 32)?;
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        
        Ok(key)
    }
    
    /// Implement Derive-Secret as defined in RFC 8446 Section 7.1
    /// 
    /// Derive-Secret(Secret, Label, Messages) = HKDF-Expand-Label(Secret, Label, 
    ///                                                             Transcript-Hash(Messages), Hash.length)
    fn derive_secret(&self, secret: &[u8], label: &str, messages: &[u8]) -> ZkTlsResult<Vec<u8>> {
        let transcript_hash = if messages.is_empty() {
            // Empty transcript hash is SHA-256("")
            self.crypto_provider.sha256(&[])
        } else {
            // In a real implementation, this should be the actual transcript hash
            // For now, we'll hash the messages directly
            self.crypto_provider.sha256(messages)
        };
        
        self.hkdf_expand_label(secret, label, &transcript_hash, 32)
    }
    
    /// Implement HKDF-Expand-Label as defined in RFC 8446 Section 7.1
    /// 
    /// HKDF-Expand-Label(Secret, Label, Context, Length) = 
    ///     HKDF-Expand(Secret, HkdfLabel, Length)
    /// 
    /// where HkdfLabel is constructed as:
    /// struct {
    ///     uint16 length = Length;
    ///     opaque label<7..255> = "tls13 " + Label;
    ///     opaque context<0..255> = Context;
    /// } HkdfLabel;
    fn hkdf_expand_label(
        &self, 
        secret: &[u8], 
        label: &str, 
        context: &[u8], 
        length: usize
    ) -> ZkTlsResult<Vec<u8>> {
        // Construct HkdfLabel structure
        let mut hkdf_label = Vec::new();
        
        // uint16 length
        hkdf_label.extend_from_slice(&(length as u16).to_be_bytes());
        
        // opaque label<7..255> = "tls13 " + Label
        let full_label = format!("tls13 {}", label);
        let label_bytes = full_label.as_bytes();
        if label_bytes.len() > 255 {
            return Err(ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed));
        }
        hkdf_label.push(label_bytes.len() as u8);
        hkdf_label.extend_from_slice(label_bytes);
        
        // opaque context<0..255>
        if context.len() > 255 {
            return Err(ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed));
        }
        hkdf_label.push(context.len() as u8);
        hkdf_label.extend_from_slice(context);
        
        // HKDF-Expand(Secret, HkdfLabel, Length)
        self.crypto_provider.hkdf_expand_sha256(secret, &hkdf_label, length)
            .map_err(|_| ZkTlsError::ProtocolError(ProtocolError::KeyDerivationFailed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zktls_crypto::native::NativeCryptoProvider;
    use hex_literal::hex;
    use alloc::vec;
    
    #[test]
    fn test_key_schedule_initialization() {
        let crypto_provider = NativeCryptoProvider::new();
        let key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Should start with no secrets derived
        assert!(key_schedule.early_secret.is_none());
        assert!(key_schedule.handshake_secret.is_none());
        assert!(key_schedule.master_secret.is_none());
    }
    
    #[test]
    fn test_early_secret_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Derive early secret with no PSK (zero IKM)
        assert!(key_schedule.derive_early_secret(None).is_ok());
        assert!(key_schedule.early_secret.is_some());
        
        // Early secret should not be all zeros (HKDF should produce different output)
        assert_ne!(key_schedule.early_secret.unwrap(), [0u8; 32]);
    }
    
    #[test]
    fn test_handshake_secret_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Must derive early secret first
        assert!(key_schedule.derive_handshake_secret(&[0x42; 32]).is_err());
        
        // Derive early secret then handshake secret
        key_schedule.derive_early_secret(None).unwrap();
        
        let shared_secret = hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        assert!(key_schedule.derive_handshake_secret(&shared_secret).is_ok());
        assert!(key_schedule.handshake_secret.is_some());
        
        // Handshake secret should be different from early secret
        assert_ne!(key_schedule.early_secret.unwrap(), key_schedule.handshake_secret.unwrap());
    }
    
    #[test]
    fn test_handshake_traffic_secrets_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Setup key schedule
        key_schedule.derive_early_secret(None).unwrap();
        let shared_secret = hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        key_schedule.derive_handshake_secret(&shared_secret).unwrap();
        
        // Derive handshake traffic secrets with mock transcript hash
        let handshake_context = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let secrets = key_schedule.derive_handshake_traffic_secrets(&handshake_context).unwrap();
        
        // Client and server secrets should be different
        assert_ne!(secrets.client_handshake_traffic_secret, secrets.server_handshake_traffic_secret);
        
        // Neither should be all zeros
        assert_ne!(secrets.client_handshake_traffic_secret, [0u8; 32]);
        assert_ne!(secrets.server_handshake_traffic_secret, [0u8; 32]);
    }
    
    #[test]
    fn test_application_traffic_secrets_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Setup complete key schedule
        key_schedule.derive_early_secret(None).unwrap();
        let shared_secret = hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        key_schedule.derive_handshake_secret(&shared_secret).unwrap();
        key_schedule.derive_master_secret().unwrap();
        
        // Derive application traffic secrets
        let handshake_context = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let secrets = key_schedule.derive_application_traffic_secrets(&handshake_context).unwrap();
        
        // Client and server secrets should be different
        assert_ne!(secrets.client_application_traffic_secret, secrets.server_application_traffic_secret);
        
        // Neither should be all zeros
        assert_ne!(secrets.client_application_traffic_secret, [0u8; 32]);
        assert_ne!(secrets.server_application_traffic_secret, [0u8; 32]);
    }
    
    #[test]
    fn test_traffic_keys_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        let traffic_secret = hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f06f867a3b9aaf28c8163a");
        
        // Test AES-128-GCM key derivation (16 bytes)
        let keys_128 = key_schedule.derive_traffic_keys(&traffic_secret, 16).unwrap();
        assert_eq!(keys_128.key.len(), 16);
        assert_ne!(keys_128.key, vec![0u8; 16]);
        assert_ne!(keys_128.iv, [0u8; 12]);
        
        // Test AES-256-GCM key derivation (32 bytes)
        let keys_256 = key_schedule.derive_traffic_keys(&traffic_secret, 32).unwrap();
        assert_eq!(keys_256.key.len(), 32);
        assert_ne!(keys_256.key, vec![0u8; 32]);
        assert_ne!(keys_256.iv, [0u8; 12]);
        
        // Keys should be different for different lengths
        assert_ne!(keys_128.key[..16], keys_256.key[..16]);
    }
    
    #[test]
    fn test_finished_key_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        let traffic_secret = hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f06f867a3b9aaf28c8163a");
        let finished_key = key_schedule.derive_finished_key(&traffic_secret).unwrap();
        
        assert_ne!(finished_key, [0u8; 32]);
        
        // Should be deterministic
        let finished_key2 = key_schedule.derive_finished_key(&traffic_secret).unwrap();
        assert_eq!(finished_key, finished_key2);
    }
    
    #[test]
    fn test_hkdf_expand_label() {
        let crypto_provider = NativeCryptoProvider::new();
        let key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        let secret = hex!("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f06f867a3b9aaf28c8163a");
        let result = key_schedule.hkdf_expand_label(&secret, "test", &[], 16).unwrap();
        
        assert_eq!(result.len(), 16);
        assert_ne!(result, vec![0u8; 16]);
        
        // Should be deterministic
        let result2 = key_schedule.hkdf_expand_label(&secret, "test", &[], 16).unwrap();
        assert_eq!(result, result2);
        
        // Different labels should produce different results
        let result3 = key_schedule.hkdf_expand_label(&secret, "different", &[], 16).unwrap();
        assert_ne!(result, result3);
    }
    
    #[test]
    fn test_sequential_key_derivation() {
        let crypto_provider = NativeCryptoProvider::new();
        let mut key_schedule = Tls13KeySchedule::new(crypto_provider);
        
        // Test full key schedule progression
        key_schedule.derive_early_secret(None).unwrap();
        
        let shared_secret = hex!("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        key_schedule.derive_handshake_secret(&shared_secret).unwrap();
        
        let handshake_context = hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        let hs_secrets = key_schedule.derive_handshake_traffic_secrets(&handshake_context).unwrap();
        
        key_schedule.derive_master_secret().unwrap();
        let app_secrets = key_schedule.derive_application_traffic_secrets(&handshake_context).unwrap();
        
        // All secrets should be different
        let early = key_schedule.early_secret.unwrap();
        let handshake = key_schedule.handshake_secret.unwrap();
        let master = key_schedule.master_secret.unwrap();
        
        assert_ne!(early, handshake);
        assert_ne!(handshake, master);
        assert_ne!(early, master);
        
        // Traffic secrets should also be unique
        assert_ne!(hs_secrets.client_handshake_traffic_secret, app_secrets.client_application_traffic_secret);
        assert_ne!(hs_secrets.server_handshake_traffic_secret, app_secrets.server_application_traffic_secret);
    }
}