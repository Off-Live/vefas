//! vefas-rustls: custom rustls CryptoProvider with ephemeral key capture

#![forbid(unsafe_code)]

pub mod provider;

use rustls::crypto::CryptoProvider;
use std::sync::{Arc, Mutex};

pub type EphemeralCaptureHandle = Arc<Mutex<Option<[u8; 32]>>>;

#[derive(Clone, Copy, Debug)]
pub struct EphemeralSeed(pub [u8; 32]);

#[derive(Clone, Debug, Default)]
pub struct ProviderConfig {
    pub seed: Option<EphemeralSeed>,
}

pub fn new_provider(config: ProviderConfig) -> (CryptoProvider, EphemeralCaptureHandle) {
    let capture: EphemeralCaptureHandle = Arc::new(Mutex::new(None));
    let provider = provider::build_capturing_provider(config, Arc::clone(&capture));
    (provider, capture)
}
