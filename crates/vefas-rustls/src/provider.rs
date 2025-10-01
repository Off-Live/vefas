use rand::rngs::ThreadRng;
use rand::RngCore;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::NamedGroup;
use std::sync::Arc;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroize;

use crate::{EphemeralCaptureHandle, EphemeralSeed, ProviderConfig};

#[derive(Debug)]
struct CapturingX25519Group {
    _label: &'static str,
    capture: EphemeralCaptureHandle,
    seed: Option<EphemeralSeed>,
}

impl CapturingX25519Group {
    fn new(capture: EphemeralCaptureHandle, seed: Option<EphemeralSeed>) -> Self {
        Self {
            _label: "X25519",
            capture,
            seed,
        }
    }
}

struct CapturingX25519Kx {
    secret: [u8; 32],
    pubkey: [u8; 32],
}

impl Drop for CapturingX25519Kx {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ActiveKeyExchange for CapturingX25519Kx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        if peer_pub_key.len() != 32 {
            return Err(rustls::Error::General("invalid peer key".into()));
        }
        let peer: [u8; 32] = <[u8; 32]>::try_from(peer_pub_key)
            .map_err(|_| rustls::Error::General("invalid key".into()))?;
        let shared = x25519(self.secret, peer);
        Ok(SharedSecret::from(shared.to_vec()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pubkey
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl SupportedKxGroup for CapturingX25519Group {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut secret: [u8; 32] = if let Some(EphemeralSeed(seed)) = self.seed {
            seed
        } else {
            let mut tmp = [0u8; 32];
            let mut rng: ThreadRng = rand::rng();
            rng.fill_bytes(&mut tmp);
            tmp
        };
        // Clamp scalar for X25519
        secret[0] &= 248;
        secret[31] &= 127;
        secret[31] |= 64;

        // publish capture
        if let Ok(mut slot) = self.capture.lock() {
            let mut bytes = secret;
            *slot = Some(bytes);
            bytes.zeroize();
        }

        let pubkey = x25519(secret, X25519_BASEPOINT_BYTES);
        let kx = CapturingX25519Kx { secret, pubkey };
        Ok(Box::new(kx))
    }
}

pub fn build_capturing_provider(
    config: ProviderConfig,
    capture: EphemeralCaptureHandle,
) -> CryptoProvider {
    // Start from aws-lc-rs defaults
    let mut provider = default_provider();

    // Leak the capturing group to obtain a 'static reference required by rustls
    let capturing = Box::new(CapturingX25519Group::new(Arc::clone(&capture), config.seed));
    let capturing_ref: &'static dyn SupportedKxGroup = Box::leak(capturing);

    // Build a new list of kx groups with our capturing X25519 first
    let mut groups: Vec<&'static dyn SupportedKxGroup> =
        Vec::with_capacity(provider.kx_groups.len() + 1);
    groups.push(capturing_ref);
    groups.extend_from_slice(&provider.kx_groups);
    provider.kx_groups = groups;

    provider
}
