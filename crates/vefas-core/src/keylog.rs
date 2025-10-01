//! TLS key logging for session secret capture
//!
//! This module implements the VefasKeyLog that captures TLS 1.3 session secrets
//! for zkTLS verification. It provides a secure, thread-safe implementation of
//! rustls::KeyLog trait with proper secret lifecycle management.
//!
//! ## Design Principles
//!
//! - **Complete TLS 1.3 support**: Captures all necessary secret labels
//! - **Thread-safe**: Arc<Mutex<>> for concurrent access
//! - **Deterministic ordering**: Consistent secret serialization
//! - **Security-conscious**: Clear secrets after use with zeroize

use crate::error::{Result, VefasCoreError};
use rustls::KeyLog;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

/// TLS 1.3 secret labels that we need to capture
pub const REQUIRED_SECRET_LABELS: &[&str] = &[
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
    "EXPORTER_SECRET",
];

/// A single captured secret entry
#[derive(Debug, Clone)]
pub struct SecretEntry {
    /// Secret label (e.g., "CLIENT_TRAFFIC_SECRET_0")
    pub label: String,
    /// Client random (32 bytes)
    pub client_random: [u8; 32],
    /// Secret bytes
    pub secret: Vec<u8>,
    /// Unix timestamp when secret was captured
    pub timestamp: u64,
}

impl SecretEntry {
    /// Create a new secret entry
    pub fn new(label: String, client_random: [u8; 32], secret: Vec<u8>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            label,
            client_random,
            secret,
            timestamp,
        }
    }

    /// Get the client random as hex string (for debugging)
    pub fn client_random_hex(&self) -> String {
        hex::encode(self.client_random)
    }

    /// Get the secret as hex string (for debugging)
    pub fn secret_hex(&self) -> String {
        hex::encode(&self.secret)
    }

    /// Clear the secret from memory
    pub fn clear_secret(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for SecretEntry {
    fn drop(&mut self) {
        self.clear_secret();
    }
}

/// Thread-safe key logger for capturing TLS session secrets
#[derive(Debug, Clone)]
pub struct VefasKeyLog {
    /// Map from client_random (hex) to secrets for that session
    sessions: Arc<Mutex<HashMap<String, HashMap<String, SecretEntry>>>>,
    /// Enable debug logging to SSLKEYLOGFILE format
    enable_debug_log: bool,
}

impl VefasKeyLog {
    /// Create a new key logger
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            enable_debug_log: false,
        }
    }

    /// Create a new key logger with debug logging enabled
    pub fn with_debug_log() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            enable_debug_log: true,
        }
    }

    /// Get all secrets for a specific client random
    pub fn get_session_secrets(
        &self,
        client_random: &[u8; 32],
    ) -> Result<HashMap<String, SecretEntry>> {
        let client_random_hex = hex::encode(client_random);
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock sessions: {}", e)))?;

        Ok(sessions
            .get(&client_random_hex)
            .cloned()
            .unwrap_or_default())
    }

    /// Get a specific secret for a client random and label
    pub fn get_secret(&self, client_random: &[u8; 32], label: &str) -> Result<Option<SecretEntry>> {
        let secrets = self.get_session_secrets(client_random)?;
        Ok(secrets.get(label).cloned())
    }

    /// Check if all required secrets have been captured for a session
    pub fn has_all_required_secrets(&self, client_random: &[u8; 32]) -> Result<bool> {
        let secrets = self.get_session_secrets(client_random)?;

        for &required_label in REQUIRED_SECRET_LABELS {
            if !secrets.contains_key(required_label) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get all captured sessions
    pub fn get_all_sessions(&self) -> Result<Vec<String>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock sessions: {}", e)))?;

        Ok(sessions.keys().cloned().collect())
    }

    /// Clear all captured secrets (for security)
    pub fn clear_all_secrets(&self) -> Result<()> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock sessions: {}", e)))?;

        for (_, session_secrets) in sessions.iter_mut() {
            for (_, secret_entry) in session_secrets.iter_mut() {
                secret_entry.clear_secret();
            }
        }

        sessions.clear();
        Ok(())
    }

    /// Get the total number of captured secrets across all sessions
    pub fn total_secret_count(&self) -> Result<usize> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock sessions: {}", e)))?;

        let count = sessions.values().map(|session| session.len()).sum();

        Ok(count)
    }

    /// Export secrets in SSLKEYLOGFILE format for debugging
    pub fn export_sslkeylogfile_format(&self) -> Result<String> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|e| VefasCoreError::internal(&format!("Failed to lock sessions: {}", e)))?;

        let mut entries: Vec<(String, String, String)> = Vec::new();
        for (_, session_secrets) in sessions.iter() {
            for (_, secret_entry) in session_secrets.iter() {
                entries.push((
                    secret_entry.label.clone(),
                    secret_entry.client_random_hex(),
                    secret_entry.secret_hex(),
                ));
            }
        }

        // Deterministic ordering: sort by label, then client_random
        entries.sort_by(|a, b| {
            let c = a.0.cmp(&b.0);
            if c == core::cmp::Ordering::Equal {
                a.1.cmp(&b.1)
            } else {
                c
            }
        });

        let mut output = String::new();
        for (label, client_random_hex, secret_hex) in entries {
            let line = format!("{} {} {}\n", label, client_random_hex, secret_hex);
            output.push_str(&line);
        }

        Ok(output)
    }

    /// Convert client random slice to fixed-size array
    fn client_random_to_array(client_random: &[u8]) -> Result<[u8; 32]> {
        if client_random.len() != 32 {
            return Err(VefasCoreError::invalid_input(&format!(
                "Client random must be 32 bytes, got {}",
                client_random.len()
            )));
        }

        let mut array = [0u8; 32];
        array.copy_from_slice(client_random);
        Ok(array)
    }
}

impl KeyLog for VefasKeyLog {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        // Convert client random to fixed array
        let client_random_array = match Self::client_random_to_array(client_random) {
            Ok(arr) => arr,
            Err(_) => {
                if self.enable_debug_log {
                    eprintln!(
                        "VefasKeyLog: Invalid client random length: {}",
                        client_random.len()
                    );
                }
                return;
            }
        };

        let client_random_hex = hex::encode(client_random_array);
        let secret_entry =
            SecretEntry::new(label.to_string(), client_random_array, secret.to_vec());

        // Log to our internal storage
        if let Ok(mut sessions) = self.sessions.lock() {
            let session_secrets = sessions.entry(client_random_hex.clone()).or_default();
            session_secrets.insert(label.to_string(), secret_entry.clone());
        } else {
            eprintln!("VefasKeyLog: Failed to acquire sessions lock");
        }

        // Optional debug logging in SSLKEYLOGFILE format
        if self.enable_debug_log {
            println!("{} {} {}", label, client_random_hex, hex::encode(secret));
        }
    }

    fn will_log(&self, label: &str) -> bool {
        // Restrict to required TLS 1.3 labels for determinism
        REQUIRED_SECRET_LABELS.contains(&label)
    }
}

impl Default for VefasKeyLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_client_random() -> [u8; 32] {
        let mut random = [0u8; 32];
        for i in 0..32 {
            random[i] = i as u8;
        }
        random
    }

    fn create_test_secret(label: &str) -> Vec<u8> {
        format!("test_secret_for_{}", label).into_bytes()
    }

    #[test]
    fn test_keylog_creation() {
        let keylog = VefasKeyLog::new();
        assert_eq!(keylog.total_secret_count().unwrap(), 0);
        assert!(keylog.get_all_sessions().unwrap().is_empty());
    }

    #[test]
    fn test_keylog_with_debug() {
        let keylog = VefasKeyLog::with_debug_log();
        assert!(keylog.enable_debug_log);
    }

    #[test]
    fn test_secret_entry_creation() {
        let client_random = create_test_client_random();
        let secret = create_test_secret("CLIENT_TRAFFIC_SECRET_0");

        let entry = SecretEntry::new(
            "CLIENT_TRAFFIC_SECRET_0".to_string(),
            client_random,
            secret.clone(),
        );

        assert_eq!(entry.label, "CLIENT_TRAFFIC_SECRET_0");
        assert_eq!(entry.client_random, client_random);
        assert_eq!(entry.secret, secret);
        assert!(entry.timestamp > 0);
    }

    #[test]
    fn test_secret_entry_hex_methods() {
        let client_random = create_test_client_random();
        let secret = create_test_secret("test");

        let entry = SecretEntry::new("test".to_string(), client_random, secret);

        assert_eq!(entry.client_random_hex(), hex::encode(client_random));
        assert!(!entry.secret_hex().is_empty());
    }

    #[test]
    fn test_keylog_logging() {
        let keylog = VefasKeyLog::new();
        let client_random = create_test_client_random();
        let secret = create_test_secret("CLIENT_TRAFFIC_SECRET_0");

        keylog.log("CLIENT_TRAFFIC_SECRET_0", &client_random, &secret);

        assert_eq!(keylog.total_secret_count().unwrap(), 1);

        let retrieved_secret = keylog
            .get_secret(&client_random, "CLIENT_TRAFFIC_SECRET_0")
            .unwrap();
        assert!(retrieved_secret.is_some());

        let secret_entry = retrieved_secret.unwrap();
        assert_eq!(secret_entry.label, "CLIENT_TRAFFIC_SECRET_0");
        assert_eq!(secret_entry.secret, secret);
    }

    #[test]
    fn test_multiple_secrets_same_session() {
        let keylog = VefasKeyLog::new();
        let client_random = create_test_client_random();

        // Log multiple secrets for the same session
        keylog.log(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            &client_random,
            &create_test_secret("handshake"),
        );
        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random,
            &create_test_secret("traffic"),
        );
        keylog.log(
            "EXPORTER_SECRET",
            &client_random,
            &create_test_secret("exporter"),
        );

        assert_eq!(keylog.total_secret_count().unwrap(), 3);

        let session_secrets = keylog.get_session_secrets(&client_random).unwrap();
        assert_eq!(session_secrets.len(), 3);
        assert!(session_secrets.contains_key("CLIENT_HANDSHAKE_TRAFFIC_SECRET"));
        assert!(session_secrets.contains_key("CLIENT_TRAFFIC_SECRET_0"));
        assert!(session_secrets.contains_key("EXPORTER_SECRET"));
    }

    #[test]
    fn test_multiple_sessions() {
        let keylog = VefasKeyLog::new();
        let client_random1 = create_test_client_random();
        let mut client_random2 = create_test_client_random();
        client_random2[0] = 0xFF; // Make it different

        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random1,
            &create_test_secret("secret1"),
        );
        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random2,
            &create_test_secret("secret2"),
        );

        assert_eq!(keylog.total_secret_count().unwrap(), 2);

        let sessions = keylog.get_all_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_will_log() {
        let keylog = VefasKeyLog::new();

        // Allowed TLS 1.3 labels only
        for &label in REQUIRED_SECRET_LABELS {
            assert!(keylog.will_log(label));
        }

        // Early-traffic labels are not logged per restriction
        assert!(!keylog.will_log("CLIENT_EARLY_TRAFFIC_SECRET"));
        assert!(!keylog.will_log("SERVER_EARLY_TRAFFIC_SECRET"));
    }

    #[test]
    fn test_has_all_required_secrets() {
        let keylog = VefasKeyLog::new();
        let client_random = create_test_client_random();

        // Initially no secrets
        assert!(!keylog.has_all_required_secrets(&client_random).unwrap());

        // Add some but not all required secrets
        keylog.log(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
            &client_random,
            &create_test_secret("handshake"),
        );
        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random,
            &create_test_secret("traffic"),
        );
        assert!(!keylog.has_all_required_secrets(&client_random).unwrap());

        // Add all required secrets
        for &label in REQUIRED_SECRET_LABELS {
            keylog.log(label, &client_random, &create_test_secret(label));
        }
        assert!(keylog.has_all_required_secrets(&client_random).unwrap());
    }

    #[test]
    fn test_clear_secrets() {
        let keylog = VefasKeyLog::new();
        let client_random = create_test_client_random();

        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random,
            &create_test_secret("secret"),
        );
        assert_eq!(keylog.total_secret_count().unwrap(), 1);

        keylog.clear_all_secrets().unwrap();
        assert_eq!(keylog.total_secret_count().unwrap(), 0);
        assert!(keylog.get_all_sessions().unwrap().is_empty());
    }

    #[test]
    fn test_sslkeylogfile_export() {
        let keylog = VefasKeyLog::new();
        let client_random = create_test_client_random();

        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &client_random,
            &create_test_secret("traffic"),
        );
        keylog.log(
            "SERVER_TRAFFIC_SECRET_0",
            &client_random,
            &create_test_secret("server"),
        );

        let export = keylog.export_sslkeylogfile_format().unwrap();

        assert!(!export.is_empty());
        assert!(export.contains("CLIENT_TRAFFIC_SECRET_0"));
        assert!(export.contains("SERVER_TRAFFIC_SECRET_0"));
        assert!(export.contains(&hex::encode(client_random)));
    }

    #[test]
    fn test_invalid_client_random() {
        let keylog = VefasKeyLog::new();
        let invalid_random = [0u8; 16]; // Too short

        // This should not panic but should be handled gracefully
        keylog.log(
            "CLIENT_TRAFFIC_SECRET_0",
            &invalid_random,
            &create_test_secret("secret"),
        );

        // The secret should not be logged due to invalid client random
        assert_eq!(keylog.total_secret_count().unwrap(), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;

        let keylog = Arc::new(VefasKeyLog::new());
        let mut handles = vec![];

        // Spawn multiple threads logging secrets
        for i in 0..10 {
            let keylog_clone = keylog.clone();
            let handle = thread::spawn(move || {
                let mut client_random = create_test_client_random();
                client_random[0] = i as u8; // Make each thread use different client random

                keylog_clone.log(
                    "CLIENT_TRAFFIC_SECRET_0",
                    &client_random,
                    &create_test_secret(&format!("secret_{}", i)),
                );
            });
            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        // Should have logged 10 secrets across 10 sessions
        assert_eq!(keylog.total_secret_count().unwrap(), 10);
        assert_eq!(keylog.get_all_sessions().unwrap().len(), 10);
    }

    #[test]
    fn test_secret_zeroization() {
        let client_random = create_test_client_random();
        let secret = create_test_secret("test");

        let mut entry = SecretEntry::new("test".to_string(), client_random, secret);

        // Secret should initially contain data
        assert!(!entry.secret.is_empty());

        // Clear the secret
        entry.clear_secret();

        // Secret should be zeroized
        assert!(entry.secret.iter().all(|&b| b == 0));
    }
}
