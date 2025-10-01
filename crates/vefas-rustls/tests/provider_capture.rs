use rustls::crypto::SupportedKxGroup;
use vefas_rustls::{new_provider, EphemeralSeed, ProviderConfig};

#[test]
fn provider_builds_and_captures_seed() {
    let seed = [0x42u8; 32];
    let (provider, capture) = new_provider(ProviderConfig {
        seed: Some(EphemeralSeed(seed)),
    });
    // Provider should have at least one kx group (our capturing + base)
    assert!(!provider.kx_groups.is_empty());

    // Start KX to trigger capture
    let kx_group: &'static dyn SupportedKxGroup = provider.kx_groups[0];
    let active = kx_group.start().expect("start kx");
    let pubkey = active.pub_key().to_vec();
    assert_eq!(pubkey.len(), 32);

    // Capture should be populated
    let captured = capture.lock().unwrap().clone();
    assert!(captured.is_some());
}
